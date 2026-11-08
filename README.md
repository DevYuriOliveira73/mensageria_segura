# mensageria_segura
Trabalho de Segurança

## Organização do cliente

- `client/cryptography/`: geração de chaves, derivação e criptografia das mensagens.
- `client/communication/`: conexão segura, handshake, framing TCP e envelopes.
- `client/application/`: processamento de mensagens/comandos e utilitários de conexão/terminal.
- `client/index.ts`: função `main`, que coordena a inicialização e o ciclo de vida do cliente.
