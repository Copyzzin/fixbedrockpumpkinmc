# bedrock-bridge

Ponte **Bedrock → Java no estilo Geyser**, empacotada como plugin WASM para o [Pumpkin](https://pumpkinmc.org), pensada para substituir o listener Bedrock nativo.

> **Leia primeiro: este é um alicerce, não um substituto pronto.**
> A camada de transporte, autenticação e o link Java estão escritos. A **sequência de entrada específica de versão** (StartGame, chunks, inventário, entidades…) **não está implementada**. Hoje um cliente Bedrock conecta, autentica e é encerrado com uma mensagem explícita. Além disso, **o código nunca foi compilado nem testado** (foi escrito sem toolchain Rust nem acesso à rede). Veja "Estado" e "Primeiros passos de verificação".

## Arquitetura

```text
Cliente Bedrock ──UDP/RakNet :19132──► bedrock-bridge (dentro do Pumpkin, WASM)
                                          │  1. RakNet (confiabilidade, split, ACK/NACK)
                                          │  2. Batch Bedrock (deflate, AES-256-CTR)
                                          │  3. Login: verifica a cadeia Xbox (ES384)
                                          │  4. Tradutores por pacote (registro estilo Geyser)
                                          ▼
                              cliente Java sobre TCP loopback ──► porta Java do Pumpkin
                                (identidade via Velocity modern forwarding, como o Floodgate)
```

- Um plugin WASM não tem threads nem runtime async: a ponte é uma máquina de estados avançada **uma vez por tick** pelo agendador, sobre sockets WASI não bloqueantes. Custo: até ~50 ms extras de latência por direção.
- Os ids de pacotes Java **não são fixos no código**: são lidos de um `packets.json` da versão exata do servidor, e o plugin falha na inicialização se algum pacote necessário sumiu ou mudou de nome.

## Estado

| Camada | Estado |
|---|---|
| RakNet (handshake, frames, split, ACK/NACK, reenvio, limites anti-abuso) | Escrito, **não testado** contra cliente real |
| Batch Bedrock + compressão + proteção contra decompression bomb | Escrito, com testes unitários |
| Criptografia (ECDH P-384 + AES-256-CTR + checksum) | Escrito a partir do esquema documentado; **validar com cliente real** |
| Login: parsing + verificação da cadeia de identidade | Escrito; formato clássico de cadeia. **Formato novo com `Token` é rejeitado** (ainda não suportado) |
| Link Java (handshake, forwarding Velocity, configuração, keep-alive, ack de chunks/teleporte) | Escrito; layouts de campos seguem a família 1.21.5+, **conferir contra a versão alvo** |
| Tradutores: chat e comandos (ambos os sentidos), disconnect | Escrito |
| **Sequência de entrada Bedrock (StartGame etc.)** | **Não implementada** (`bridge/join.rs`, `NotImplemented`) |
| Movimento, chunks/blocos, inventário/itens, entidades, efeitos, scoreboard, formulários | **Não implementado** |

## Pré-requisitos no Pumpkin

1. **Desligar o Bedrock nativo** para liberar a UDP 19132 (nas docs consultadas a chave é `bedrock_edition = false`; confirme o nome na sua versão).
2. **Ativar Velocity forwarding** (`[proxy] enabled = true` e `[proxy.velocity] enabled = true, secret = "..."`). O mesmo segredo vai em `java.forwarding_secret`.
3. **Consequência importante:** com forwarding ligado, o Pumpkin **recusa logins Java diretos**. Jogadores Java precisam entrar por um proxy (ex.: Velocity), ou a porta Java deve ficar acessível só para esta ponte. Um front Java dentro do plugin (como faz o plugin Multiversion) está no roadmap.
4. Habilitar plugins e **pré-aprovar as permissões** do plugin: `fs.read.data`, `fs.write.data`, `network.udp`, `network.udp.bind`, `network.udp.outgoing_datagram`, `network.tcp`, `network.tcp.connect`.

## Dados que você precisa fornecer

- **`java_packets.json`**: rode o data generator do servidor vanilla da versão do Pumpkin  
  `java -DbundlerMainClass=net.minecraft.data.Main -jar server.jar --reports`  
  e copie `generated/reports/packets.json` para `plugins/data/bedrock-bridge/java_packets.json`.
- **`java.protocol_version`**: campo `protocol_version` do `version.json` do mesmo servidor.
- **`bedrock.protocol`**: número de protocolo do Bedrock alvo.
- **`auth.mojang_root_public_keys`**: chave(s) pública(s) raiz (base64 DER/SPKI) que assinam a cadeia de login Xbox. **Não vêm embutidas de propósito**: um valor errado numa constante de segurança é pior do que exigir configuração explícita. Obtenha-as de fonte confiável (ex.: o código-fonte do Geyser) e confirme.

## Montar o plugin

```bash
./build.sh                # Linux/macOS: instala o target se faltar, testa (se houver wasmtime), compila e empacota
```

```bat
build.bat                 :: Windows: faz o mesmo (duplo clique também funciona)
```

Variáveis opcionais, nos dois scripts: `SKIP_TESTS=1` pula os testes. No Windows, `NO_PAUSE=1` evita a pausa final quando o script é chamado por outro programa.

**Windows: o erro `linker link.exe not found`.** O Rust no Windows precisa do linker do Visual Studio até para compilar os scripts de build das dependências (`serde`, `quote`…), mesmo quando o alvo final é WASM. Escolha uma das saídas:

1. Instale o **Build Tools for Visual Studio** (na página de downloads do Visual Studio, em "Tools for Visual Studio") marcando a carga de trabalho **"Desktop development with C++"**. Depois abra um terminal novo e rode `build.bat` de novo. O VS Code não substitui isso.
2. Use **WSL2** (Ubuntu) com Rust instalado e rode `./build.sh`.
3. Faça push para o GitHub e deixe a CI compilar no Linux (`.github/workflows/build.yml`), sem instalar nada localmente.

Resultado:

```text
dist/bedrock-bridge/
├── plugins/
│   ├── bedrock-bridge.wasm                 o plugin (componente WASM)
│   └── data/bedrock-bridge/config.toml     modelo de configuração
├── pumpkin-config.snippet.toml             o que mudar no Pumpkin
├── INSTALL.md
└── README.md
dist/bedrock-bridge-<versão>.zip            o mesmo, compactado
```

Copie o conteúdo de `dist/bedrock-bridge/` para a pasta do servidor e siga `INSTALL.md`. Sem Rust local, faça push para o GitHub: `.github/workflows/build.yml` roda o mesmo script e publica o `.zip` como artefato (e anexa à release em tags `v*`).

Build manual, se preferir: `cargo build --release` (o target `wasm32-wasip2` já está em `.cargo/config.toml`) e use `target/wasm32-wasip2/release/bedrock_bridge.wasm` como `plugins/bedrock-bridge.wasm`.

## Primeiros passos de verificação (faça nesta ordem)

1. `cargo build` e corrija erros de compilação. Pontos mais prováveis, por dependerem de APIs que confirmei só pela documentação:
   - assinaturas de `Plugin::on_load`/`on_unload`, `scheduler::cancel_task` e nomes em `permissions::*` (`pumpkin-plugin-api` ainda é "early stage" e muda);
   - tipos do crate `wasi` (`sockets::udp`, `sockets::tcp`, `io::streams`) e `random::random::get_random_bytes`;
   - features do `p384` (`ecdh`, `ecdsa`, `pkcs8`).
2. `cargo test` (de preferência com Wasmtime como runner, ver `.cargo/config.toml`). Há testes para varints, RakNet (frames, ACK, split), batch/compressão, criptografia, forwarding, NBT e ids.
3. Suba com `auth.mode = "online"` e um cliente real: deve chegar até o disconnect "join sequence … not implemented". Aí você valida RakNet, NetworkSettings, Login, criptografia e o login Java via forwarding.
4. Só então implemente `JoinSequence` para o protocolo alvo.

## Segurança

- `online` é o padrão e **falha fechado**: sem chave raiz configurada, o plugin não inicia. A cadeia é verificada ponta a ponta (assinatura de cada JWT, continuidade das chaves, raiz confiável, JWT de dados do cliente). Modo `offline` permite personificar qualquer jogador (foi o bug CVE-2021-39177 do Geyser): só para testes/LAN.
- Todo dado de rede é lido com `Reader` limitado (sem `unwrap`/índices soltos). Limites por par: fila de envio, fragmentos abertos, backlog de ordenação, tamanho de batch descomprimido, sessões totais e por IP, prazo de handshake.
- RakNet do Bedrock não tem cookie anti-spoof de origem: os limites acima reduzem o dano, mas não impedem exaustão por IPs forjados. Use firewall/rate limit na borda se o servidor for público.
- Permissões mínimas: sem DNS, HTTP, variáveis de ambiente ou info de sistema.

## Limitações conhecidas

- Só IPv4 (a porta IPv6 do Bedrock, 19133, não é atendida); `java.address` e `bedrock.bind_address` são literais IP.
- Frames RakNet "sequenced" são entregues sem ordenação estrita; wrap-around de 24 bits em sequências é tratado de forma aproximada.
- Skins/propriedades de perfil não são encaminhadas ao lado Java.
- UUID Java do jogador Bedrock = `(0, XUID)` (convenção Floodgate).

## Roadmap sugerido

1. `JoinSequence` para um protocolo (gere layouts a partir da documentação oficial de protocolo do Bedrock em vez de escrever à mão).
2. Mapeamentos de estados de bloco Java ↔ Bedrock e tradutor de chunks (reaproveite os dados de mapeamento do Geyser, que é MIT, em vez de recriá-los).
3. Movimento (`PlayerAuthInput` → posição Java) e teleporte.
4. Inventário/itens, depois entidades.
5. Verificador do login por `Token` (OpenID) via `http.outbound`.
6. Front TCP Java dentro do plugin, para dispensar o proxy externo.

## Alternativa a considerar

O Pumpkin já tem suporte Bedrock nativo em evolução e a API de plugins expõe `bedrock_packets`/`BedrockPlayer`/`forms`. Se o objetivo é **estender** o Bedrock (formulários, comandos, filtros) em vez de **substituí-lo**, usar essa API dentro do servidor evita reimplementar o protocolo inteiro.
