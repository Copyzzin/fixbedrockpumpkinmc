//! Per-connection RakNet reliability layer.
//!
//! Implemented: reliable/ordered/unreliable frames, split-packet reassembly, ACK/NACK,
//! duplicate suppression, resend on timeout, MTU-aware datagram packing.
//! Simplified on purpose: "sequenced" frames are delivered unordered (Bedrock does not rely
//! on them) and 24-bit sequence wrap-around is only loosely handled (hours of sustained traffic).
//!
//! Every limit below bounds memory per peer so a hostile client cannot exhaust the plugin.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use super::write_addr;
use crate::util::{Error, Reader, Result, Writer};

pub const FLAG_ACK: u8 = 0x40;
pub const FLAG_NACK: u8 = 0x20;

const ORDER_CHANNELS: usize = 32;
const RESEND_AFTER: Duration = Duration::from_millis(900);
const SESSION_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_SEND_QUEUE_BYTES: usize = 4 * 1024 * 1024;
const MAX_IN_FLIGHT: usize = 4096;
const MAX_DATAGRAMS_PER_FLUSH: usize = 128;
const MAX_SPLIT_PARTS: u32 = 1024;
const MAX_SPLIT_BYTES: usize = 4 * 1024 * 1024;
const MAX_OPEN_SPLITS: usize = 16;
const MAX_ORDER_BACKLOG: usize = 2048;
const IP_UDP_OVERHEAD: usize = 28;
const DATAGRAM_HEADER: usize = 4;
const FRAME_MARGIN: usize = 24;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SessionState {
    Connecting,
    Connected,
}

pub enum SessionEvent {
    /// The client finished the RakNet connection handshake.
    Connected,
    /// One Bedrock game payload (the bytes after the 0xFE marker).
    Packet(Vec<u8>),
}

#[derive(Clone, Copy)]
struct Split {
    count: u32,
    id: u16,
    index: u32,
}

#[derive(Clone)]
struct Frame {
    reliability: u8,
    reliable_index: u32,
    order_index: u32,
    order_channel: u8,
    split: Option<Split>,
    payload: Vec<u8>,
}

fn is_reliable(r: u8) -> bool {
    matches!(r, 2 | 3 | 4 | 6 | 7)
}
fn is_sequenced(r: u8) -> bool {
    matches!(r, 1 | 4)
}
fn is_ordered(r: u8) -> bool {
    matches!(r, 1 | 3 | 4 | 7)
}

fn frame_len(f: &Frame) -> usize {
    3 + if is_reliable(f.reliability) { 3 } else { 0 }
        + if is_sequenced(f.reliability) { 3 } else { 0 }
        + if is_ordered(f.reliability) { 4 } else { 0 }
        + if f.split.is_some() { 10 } else { 0 }
        + f.payload.len()
}

fn read_frame(r: &mut Reader) -> Result<Frame> {
    let flags = r.u8()?;
    let reliability = flags >> 5;
    let bits = r.u16_be()? as usize;
    let len = bits.div_ceil(8);
    if len == 0 {
        return Err(Error::Invalid("empty frame"));
    }
    let mut f = Frame {
        reliability,
        reliable_index: 0,
        order_index: 0,
        order_channel: 0,
        split: None,
        payload: Vec::new(),
    };
    if is_reliable(reliability) {
        f.reliable_index = r.u24_le()?;
    }
    if is_sequenced(reliability) {
        r.u24_le()?; // sequence index: unused (see module docs)
    }
    if is_ordered(reliability) {
        f.order_index = r.u24_le()?;
        f.order_channel = r.u8()?;
        if f.order_channel as usize >= ORDER_CHANNELS {
            return Err(Error::Invalid("order channel"));
        }
    }
    if flags & 0x10 != 0 {
        let count = r.u32_be()?;
        let id = r.u16_be()?;
        let index = r.u32_be()?;
        if count == 0 || count > MAX_SPLIT_PARTS || index >= count {
            return Err(Error::Invalid("split header"));
        }
        f.split = Some(Split { count, id, index });
    }
    f.payload = r.take(len)?.to_vec();
    Ok(f)
}

fn write_frame(w: &mut Writer, f: &Frame) {
    w.u8((f.reliability << 5) | if f.split.is_some() { 0x10 } else { 0 });
    w.u16_be((f.payload.len() * 8) as u16);
    if is_reliable(f.reliability) {
        w.u24_le(f.reliable_index);
    }
    if is_sequenced(f.reliability) {
        w.u24_le(0);
    }
    if is_ordered(f.reliability) {
        w.u24_le(f.order_index);
        w.u8(f.order_channel);
    }
    if let Some(s) = f.split {
        w.u32_be(s.count);
        w.u16_be(s.id);
        w.u32_be(s.index);
    }
    w.bytes(&f.payload);
}

/// Parse the record list of an ACK/NACK datagram into sequence numbers.
fn parse_records(data: &[u8]) -> Result<Vec<u32>> {
    let mut r = Reader::new(data.get(1..).ok_or(Error::Eof)?);
    let count = r.u16_be()?;
    let mut out = Vec::new();
    for _ in 0..count {
        let single = r.u8()? != 0;
        let start = r.u24_le()?;
        let end = if single { start } else { r.u24_le()? };
        if end < start || end - start > 4096 {
            return Err(Error::Invalid("ack range"));
        }
        out.extend(start..=end);
        if out.len() > 8192 {
            return Err(Error::Limit("ack records"));
        }
    }
    Ok(out)
}

/// Encode sequence numbers as one or more ACK (0xC0) / NACK (0xA0) datagrams.
fn encode_records(tag: u8, seqs: &mut Vec<u32>, max_len: usize) -> Vec<Vec<u8>> {
    seqs.sort_unstable();
    seqs.dedup();
    let mut ranges: Vec<(u32, u32)> = Vec::new();
    for &s in seqs.iter() {
        let extend = matches!(ranges.last(), Some(&(_, end)) if end + 1 == s);
        if extend {
            if let Some(last) = ranges.last_mut() {
                last.1 = s;
            }
        } else {
            ranges.push((s, s));
        }
    }
    seqs.clear();
    let per_packet = (max_len.saturating_sub(3) / 7).max(1);
    ranges
        .chunks(per_packet)
        .map(|chunk| {
            let mut w = Writer::new();
            w.u8(tag);
            w.u16_be(chunk.len() as u16);
            for &(a, b) in chunk {
                if a == b {
                    w.u8(1);
                    w.u24_le(a);
                } else {
                    w.u8(0);
                    w.u24_le(a);
                    w.u24_le(b);
                }
            }
            w.finish()
        })
        .collect()
}

struct SplitAssembly {
    parts: Vec<Option<Vec<u8>>>,
    received: u32,
    bytes: usize,
}

struct Sent {
    frames: Vec<Frame>,
    at: Instant,
}

pub struct RakSession {
    pub addr: SocketAddrV4,
    pub guid: i64,
    pub state: SessionState,
    pub created: Instant,
    closed: Option<&'static str>,
    mtu: usize,
    epoch: Instant,
    last_recv: Instant,

    // receive side
    expected_seq: u32,
    seq_seen: BTreeSet<u32>,
    reliable_seen: BTreeSet<u32>,
    ack_queue: Vec<u32>,
    nack_queue: Vec<u32>,
    next_order_in: [u32; ORDER_CHANNELS],
    order_pending: Vec<BTreeMap<u32, Vec<u8>>>,
    splits: HashMap<u16, SplitAssembly>,

    // send side
    next_seq: u32,
    next_reliable: u32,
    next_order_out: [u32; ORDER_CHANNELS],
    next_split_id: u16,
    send_queue: VecDeque<Frame>,
    queued_bytes: usize,
    in_flight: HashMap<u32, Sent>,
}

impl RakSession {
    pub fn new(addr: SocketAddrV4, guid: i64, mtu: usize, now: Instant) -> Self {
        Self {
            addr,
            guid,
            state: SessionState::Connecting,
            created: now,
            closed: None,
            mtu: mtu.max(IP_UDP_OVERHEAD + 400),
            epoch: now,
            last_recv: now,
            expected_seq: 0,
            seq_seen: BTreeSet::new(),
            reliable_seen: BTreeSet::new(),
            ack_queue: Vec::new(),
            nack_queue: Vec::new(),
            next_order_in: [0; ORDER_CHANNELS],
            order_pending: (0..ORDER_CHANNELS).map(|_| BTreeMap::new()).collect(),
            splits: HashMap::new(),
            next_seq: 0,
            next_reliable: 0,
            next_order_out: [0; ORDER_CHANNELS],
            next_split_id: 0,
            send_queue: VecDeque::new(),
            queued_bytes: 0,
            in_flight: HashMap::new(),
        }
    }

    pub fn closed_reason(&self) -> Option<&'static str> {
        self.closed
    }

    pub fn timed_out(&self, now: Instant) -> bool {
        now.duration_since(self.last_recv) > SESSION_TIMEOUT
    }

    fn now_ms(&self, now: Instant) -> i64 {
        now.duration_since(self.epoch).as_millis() as i64
    }

    fn max_datagram(&self) -> usize {
        self.mtu - IP_UDP_OVERHEAD
    }

    fn max_frame_payload(&self) -> usize {
        self.max_datagram() - DATAGRAM_HEADER - FRAME_MARGIN
    }

    // ---------------------------------------------------------------- receive

    pub fn on_datagram(&mut self, data: &[u8], now: Instant) -> Result<Vec<SessionEvent>> {
        self.last_recv = now;
        let mut out = Vec::new();
        let Some(&flags) = data.first() else {
            return Ok(out);
        };
        if flags & FLAG_ACK != 0 {
            for seq in parse_records(data)? {
                self.in_flight.remove(&seq);
            }
            return Ok(out);
        }
        if flags & FLAG_NACK != 0 {
            for seq in parse_records(data)? {
                if let Some(sent) = self.in_flight.remove(&seq) {
                    self.requeue(sent.frames);
                }
            }
            return Ok(out);
        }
        let mut r = Reader::new(&data[1..]);
        let seq = r.u24_le()?;
        self.ack_queue.push(seq);
        if !self.note_sequence(seq) {
            return Ok(out); // duplicate datagram (already ACKed above)
        }
        while r.remaining() > 0 {
            let frame = read_frame(&mut r)?;
            self.on_frame(frame, now, &mut out)?;
        }
        Ok(out)
    }

    /// Track datagram sequence numbers; returns false for duplicates and queues NACKs for gaps.
    fn note_sequence(&mut self, seq: u32) -> bool {
        if !self.seq_seen.insert(seq) {
            return false;
        }
        if seq > self.expected_seq {
            let gap = (seq - self.expected_seq).min(256);
            for s in self.expected_seq..self.expected_seq + gap {
                if !self.seq_seen.contains(&s) {
                    self.nack_queue.push(s);
                }
            }
            self.expected_seq = seq + 1;
        } else if seq == self.expected_seq {
            self.expected_seq += 1;
        }
        while self.seq_seen.len() > 4096 {
            self.seq_seen.pop_first();
        }
        true
    }

    fn on_frame(&mut self, f: Frame, now: Instant, out: &mut Vec<SessionEvent>) -> Result<()> {
        if is_reliable(f.reliability) {
            if !self.reliable_seen.insert(f.reliable_index) {
                return Ok(());
            }
            while self.reliable_seen.len() > 8192 {
                self.reliable_seen.pop_first();
            }
        }
        let f = match f.split {
            Some(split) => match self.add_split(f, split)? {
                Some(whole) => whole,
                None => return Ok(()),
            },
            None => f,
        };
        // Only the strictly ordered types (3 and 7) are buffered; see module docs.
        if matches!(f.reliability, 3 | 7) {
            self.deliver_ordered(f, now, out)
        } else {
            self.handle_message(f.payload, now, out)
        }
    }

    fn add_split(&mut self, mut f: Frame, split: Split) -> Result<Option<Frame>> {
        if !self.splits.contains_key(&split.id) {
            if self.splits.len() >= MAX_OPEN_SPLITS {
                return Err(Error::Limit("open split packets"));
            }
            self.splits.insert(
                split.id,
                SplitAssembly { parts: vec![None; split.count as usize], received: 0, bytes: 0 },
            );
        }
        let done = {
            let Some(asm) = self.splits.get_mut(&split.id) else {
                return Ok(None);
            };
            if asm.parts.len() != split.count as usize {
                return Err(Error::Invalid("split count changed"));
            }
            let idx = split.index as usize;
            if asm.parts[idx].is_some() {
                return Ok(None);
            }
            asm.bytes += f.payload.len();
            if asm.bytes > MAX_SPLIT_BYTES {
                return Err(Error::Limit("split packet size"));
            }
            asm.parts[idx] = Some(std::mem::take(&mut f.payload));
            asm.received += 1;
            asm.received == split.count
        };
        if !done {
            return Ok(None);
        }
        let Some(asm) = self.splits.remove(&split.id) else {
            return Ok(None);
        };
        let mut whole = Vec::with_capacity(asm.bytes);
        for part in asm.parts.into_iter().flatten() {
            whole.extend_from_slice(&part);
        }
        f.payload = whole;
        f.split = None;
        Ok(Some(f))
    }

    fn deliver_ordered(&mut self, f: Frame, now: Instant, out: &mut Vec<SessionEvent>) -> Result<()> {
        let ch = f.order_channel as usize;
        let next = self.next_order_in[ch];
        if f.order_index == next {
            self.next_order_in[ch] = next.wrapping_add(1) & 0x00ff_ffff;
            self.handle_message(f.payload, now, out)?;
            loop {
                let key = self.next_order_in[ch];
                let Some(p) = self.order_pending[ch].remove(&key) else {
                    break;
                };
                self.next_order_in[ch] = key.wrapping_add(1) & 0x00ff_ffff;
                self.handle_message(p, now, out)?;
            }
        } else if f.order_index > next {
            let backlog: usize = self.order_pending.iter().map(BTreeMap::len).sum();
            if backlog >= MAX_ORDER_BACKLOG {
                return Err(Error::Limit("ordered backlog"));
            }
            self.order_pending[ch].insert(f.order_index, f.payload);
        }
        // order_index < next: stale duplicate, drop.
        Ok(())
    }

    /// Connected-protocol messages carried inside frames.
    fn handle_message(&mut self, mut p: Vec<u8>, now: Instant, out: &mut Vec<SessionEvent>) -> Result<()> {
        let Some(&id) = p.first() else {
            return Ok(());
        };
        match id {
            0xfe => {
                if self.state == SessionState::Connected {
                    p.drain(..1);
                    out.push(SessionEvent::Packet(p));
                }
            }
            0x09 => {
                // Connection Request -> Connection Request Accepted
                let mut r = Reader::new(&p[1..]);
                let _client_guid = r.i64_be()?;
                let request_time = r.i64_be()?;
                let mut w = Writer::new();
                w.u8(0x10);
                write_addr(&mut w, self.addr);
                w.u16_be(0);
                for _ in 0..10 {
                    write_addr(&mut w, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
                }
                w.i64_be(request_time);
                w.i64_be(self.now_ms(now));
                self.queue_message(w.finish(), 0)?;
            }
            0x13 => {
                if self.state == SessionState::Connecting {
                    self.state = SessionState::Connected;
                    out.push(SessionEvent::Connected);
                }
            }
            0x00 => {
                // Connected Ping -> Connected Pong
                let mut r = Reader::new(&p[1..]);
                let ping_time = r.i64_be()?;
                let mut w = Writer::new();
                w.u8(0x03);
                w.i64_be(ping_time);
                w.i64_be(self.now_ms(now));
                self.queue_message(w.finish(), 0)?;
            }
            0x15 => self.closed = Some("client disconnected"),
            _ => {}
        }
        Ok(())
    }

    // ------------------------------------------------------------------- send

    /// Queue a Bedrock game payload (reliable, ordered on channel 0, prefixed with 0xFE).
    pub fn send_game(&mut self, payload: Vec<u8>) -> Result<()> {
        let mut framed = Vec::with_capacity(payload.len() + 1);
        framed.push(0xfe);
        framed.extend_from_slice(&payload);
        self.queue_message(framed, 3)
    }

    pub fn disconnect(&mut self) {
        let _ = self.queue_message(vec![0x15], 0);
        self.closed = Some("disconnected by server");
    }

    fn queue_message(&mut self, payload: Vec<u8>, reliability: u8) -> Result<()> {
        if self.queued_bytes + payload.len() > MAX_SEND_QUEUE_BYTES {
            self.closed = Some("send queue overflow");
            return Err(Error::Limit("raknet send queue"));
        }
        let ordered = reliability == 3;
        let order_index = if ordered {
            let i = self.next_order_out[0];
            self.next_order_out[0] = (i + 1) & 0x00ff_ffff;
            i
        } else {
            0
        };
        let chunk = self.max_frame_payload();
        let pieces: Vec<&[u8]> = payload.chunks(chunk).collect();
        let split_id = self.next_split_id;
        if pieces.len() > 1 {
            self.next_split_id = self.next_split_id.wrapping_add(1);
        }
        let count = pieces.len() as u32;
        for (i, piece) in pieces.iter().enumerate() {
            let reliable_index = if is_reliable(reliability) {
                let r = self.next_reliable;
                self.next_reliable = (r + 1) & 0x00ff_ffff;
                r
            } else {
                0
            };
            let split = (count > 1).then_some(Split { count, id: split_id, index: i as u32 });
            self.queued_bytes += piece.len();
            self.send_queue.push_back(Frame {
                reliability,
                reliable_index,
                order_index,
                order_channel: 0,
                split,
                payload: piece.to_vec(),
            });
        }
        Ok(())
    }

    fn requeue(&mut self, frames: Vec<Frame>) {
        for f in frames.into_iter().rev() {
            self.queued_bytes += f.payload.len();
            self.send_queue.push_front(f);
        }
    }

    /// Produce all datagrams that should go out now: ACK/NACK, resends, then new frames.
    pub fn flush(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let max = self.max_datagram();
        out.extend(encode_records(0xc0, &mut self.ack_queue, max));
        out.extend(encode_records(0xa0, &mut self.nack_queue, max));

        let expired: Vec<u32> = self
            .in_flight
            .iter()
            .filter(|(_, s)| now.duration_since(s.at) >= RESEND_AFTER)
            .map(|(seq, _)| *seq)
            .collect();
        for seq in expired {
            if let Some(sent) = self.in_flight.remove(&seq) {
                self.requeue(sent.frames);
            }
        }

        let mut budget = MAX_DATAGRAMS_PER_FLUSH;
        while budget > 0 && !self.send_queue.is_empty() && self.in_flight.len() < MAX_IN_FLIGHT {
            let seq = self.next_seq;
            self.next_seq = (seq + 1) & 0x00ff_ffff;
            let mut w = Writer::new();
            w.u8(0x84);
            w.u24_le(seq);
            let mut reliable_frames = Vec::new();
            loop {
                let size = match self.send_queue.front() {
                    Some(f) => frame_len(f),
                    None => break,
                };
                let has_frames = w.len() > DATAGRAM_HEADER;
                if has_frames && w.len() + size > max {
                    break;
                }
                let Some(f) = self.send_queue.pop_front() else {
                    break;
                };
                self.queued_bytes = self.queued_bytes.saturating_sub(f.payload.len());
                write_frame(&mut w, &f);
                if is_reliable(f.reliability) {
                    reliable_frames.push(f);
                }
            }
            out.push(w.finish());
            if !reliable_frames.is_empty() {
                self.in_flight.insert(seq, Sent { frames: reliable_frames, at: now });
            }
            budget -= 1;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_records_roundtrip() {
        let mut seqs = vec![5, 3, 4, 10, 3, 11, 12, 100];
        let packets = encode_records(0xc0, &mut seqs, 1400);
        assert_eq!(packets.len(), 1);
        assert_eq!(parse_records(&packets[0]).unwrap(), vec![3, 4, 5, 10, 11, 12, 100]);
    }

    #[test]
    fn frame_roundtrip_with_split() {
        let f = Frame {
            reliability: 3,
            reliable_index: 7,
            order_index: 2,
            order_channel: 0,
            split: Some(Split { count: 3, id: 9, index: 1 }),
            payload: vec![1, 2, 3, 4],
        };
        let mut w = Writer::new();
        write_frame(&mut w, &f);
        let bytes = w.finish();
        assert_eq!(bytes.len(), frame_len(&f));
        let back = read_frame(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(back.payload, f.payload);
        assert_eq!(back.order_index, 2);
        assert_eq!(back.split.map(|s| (s.count, s.id, s.index)), Some((3, 9, 1)));
    }

    #[test]
    fn oversized_message_is_split_and_fits_mtu() {
        let now = Instant::now();
        let mut s = RakSession::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1), 1, 1200, now);
        s.state = SessionState::Connected;
        s.send_game(vec![0xab; 10_000]).unwrap();
        let datagrams = s.flush(now);
        assert!(datagrams.len() > 1);
        assert!(datagrams.iter().all(|d| d.len() <= 1200 - IP_UDP_OVERHEAD));
    }
}
