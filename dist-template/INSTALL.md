# Instalação do bedrock-bridge

Este pacote contém:

```text
plugins/bedrock-bridge.wasm                     o plugin (componente WASM)
plugins/data/bedrock-bridge/config.toml         configuração (preencha os campos REQUIRED)
pumpkin-config.snippet.toml                     o que mudar na configuração do Pumpkin
README.md                                       arquitetura, segurança, limitações
```

## Passos

1. **Copie `plugins/`** para a pasta do seu servidor Pumpkin (mescle com a `plugins/` existente).
2. **Configure o Pumpkin** conforme `pumpkin-config.snippet.toml`: Bedrock nativo desligado, Velocity forwarding ligado com um segredo longo e aleatório, e as permissões do plugin concedidas.
3. **Gere o `java_packets.json`** com o data generator do servidor vanilla da mesma versão que o Pumpkin implementa:
   ```bash
   java -DbundlerMainClass=net.minecraft.data.Main -jar server.jar --reports
   cp generated/reports/packets.json <pumpkin>/plugins/data/bedrock-bridge/java_packets.json
   ```
4. **Edite `plugins/data/bedrock-bridge/config.toml`** e preencha:
   - `bedrock.protocol` e `java.protocol_version` (este último está no `version.json` do server.jar);
   - `java.forwarding_secret` (igual ao `secret` do Pumpkin);
   - `auth.mojang_root_public_keys` (chaves raiz do login Xbox, de fonte confiável; veja o README).
5. **Abra a UDP 19132** no firewall. **Não** exponha a porta Java do Pumpkin publicamente enquanto o forwarding estiver ligado.
6. Inicie o Pumpkin e confira o log: deve aparecer "Bedrock listener on ...". O plugin se recusa a iniciar, com a lista do que falta, se algum campo obrigatório estiver vazio.

## O que esperar nesta versão

Um cliente Bedrock conecta, autentica e é desconectado com a mensagem "join sequence … not implemented": a entrada no mundo (StartGame, chunks etc.) ainda não foi implementada. Isso já valida RakNet, criptografia, login Xbox e o link Java com forwarding. Detalhes e roadmap no README.
