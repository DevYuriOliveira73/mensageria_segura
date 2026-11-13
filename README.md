# Mensageria_segura
Trabalho de Segurança

## Organização do cliente

- `client/cryptography/`: geração de chaves, derivação e criptografia das mensagens.
- `client/communication/`: conexão segura, handshake, framing TCP e envelopes.
- `client/application/`: processamento de mensagens/comandos e utilitários de conexão/terminal.
- `client/index.ts`: função `main`, que coordena a inicialização e o ciclo de vida do cliente.

## Organização do Servidor

- `server/src/crypto/crypto.py`: Troca de chaves, obteção de segredo, derivação das chaves e algoritmo aes-128-gcm
- `server/src/crypto/rwriter.py`: Objeto especial usado apenas na troca de chaves e construção do dicionário da sessão

- `server/src/core.py`: "Coração" do servidor, recebe as conexões, redireciona elas pro handshake, armazena as estruturas de dados e direciona as mensagens pros respectivos destinatários
- `server/src/stream.py`: Objetos para leitura e escrita nos sockets
- `server/src/utils.py`: Funções utilitárias