# Protocolo observado no servidor

> Este documento descreve o formato de rede implementado pelo servidor e pelo
> cliente. As decisões temporárias para divergências em relação ao PDF estão
> identificadas abaixo e detalhadas em `DIVIDA_TECNICA.md`.

## Convenções

- Conexão: TCP, cliente ↔ servidor.
- `||` significa concatenação de bytes.
- Inteiros do framing e contadores binários são unsigned, big-endian.
- JSON é codificado em UTF-8. Os tamanhos dos campos JSON variam; não há
  comprimento fixo para um objeto JSON.
- Base64 indica bytes codificados como texto ASCII dentro de uma string JSON.
- `client_id` é enviado como string UUID; quando usado no AAD C2S, o servidor o
  converte aos 16 bytes do UUID (`uuid.UUID(client_id).bytes`).

## 1. Handshake e autenticação do servidor

### 1.1. Registro enviado pelo cliente

O cliente envia um objeto JSON UTF-8 sem prefixo de comprimento, terminador ou
delimitador:

| Ordem lógica | Campo JSON | Valor |
|---|---|---|
| 1 | `client_id` | String UUID do cliente. |
| 2 | `pkey` | Chave pública X25519 do cliente, 32 bytes raw codificados em Base64. |

O servidor faz uma única leitura de até 1024 bytes para obter esse JSON. Não há
framing de handshake definido no código.

### 1.2. Resposta de handshake do servidor

O servidor responde com um objeto JSON UTF-8, também sem prefixo de comprimento,
terminador ou delimitador:

| Campo JSON | Valor |
|---|---|
| `pk_S` | Chave pública X25519 efêmera do servidor, 32 bytes raw em Base64. |
| `server_crt` | Certificado PEM do servidor, codificado em Base64. |
| `signature` | Assinatura RSA-PSS/SHA-256 codificada em Base64. |
| `salt_srv` | Salt aleatório de 16 bytes em Base64. |

A assinatura verifica o hash SHA-256 dos bytes concatenados:

```text
pk_S_raw (32B) || pk_C_raw (32B) || client_id_utf8 (tamanho variável) || salt_srv (16B)
```

O servidor usa RSA-PSS com SHA-256. O segredo X25519 é usado como IKM para
derivar as chaves de transporte:

```text
c2s_key = HKDF-SHA256(IKM=Z, salt=salt_srv, info="c2s", L=16)
s2c_key = HKDF-SHA256(IKM=Z, salt=salt_srv, info="s2c", L=16)
```

Essas são chaves cliente-servidor, não as chaves E2E entre dois clientes.

### 1.3. Erro no handshake

O código não define uma resposta de erro de handshake válida. O caminho de JSON
inválido tenta chamar `write` com argumentos incompatíveis com a assinatura
desse método; o servidor captura a exceção no nível do handshake e encerra a
tentativa de sessão.

## 2. Frame binário de transporte cliente-servidor

Após o handshake, os bytes no socket têm esta estrutura:

| Ordem | Campo | Tamanho | Codificação |
|---|---|---:|---|
| 1 | `tcp_frame_len` | 4 bytes | Unsigned big-endian; número de bytes seguintes, sem contar este prefixo. |
| 2 | `nonce` | 12 bytes | `IV_base (4B) || seq_no (8B)`. |
| 3 | `seq_no` | 8 bytes | Unsigned big-endian. |
| 4 | `ciphertext` | Variável | Saída AES-GCM sem a tag. |
| 5 | `tag` | 16 bytes | Tag AES-GCM, concatenada ao ciphertext. |

Portanto, o corpo do frame tem `36 + tamanho(plaintext)` bytes. O prefixo conta
o corpo inteiro: nonce, contador, ciphertext e tag. O cliente limita o corpo a
8192 bytes.

O servidor gera `IV_base` de 4 bytes por sessão e não o envia no handshake. O
cliente gera seu próprio `IV_base` C2S. Cada lado aprende o IV de recebimento
pelos 4 primeiros bytes do primeiro nonce autenticado. O nonce não é duplicado
em campo separado dentro do frame: é transmitido uma vez, antes do contador. A
implementação também envia o contador separadamente, embora ele já faça parte
do nonce.

### 2.1. AES-GCM e AAD de transporte

| Direção | Chave | AAD |
|---|---|---|
| Cliente → servidor | `c2s_key` | `UUID(client_id).bytes (16B) || seq_no (8B)` |
| Servidor → cliente | `s2c_key` | ASCII `server` (6B) `|| seq_no (8B)` |

O cliente deve incrementar seu contador de envio e o contador de recebimento
separadamente. O servidor inicializa ambos em zero e rejeita frames C2S cujo
contador não seja o próximo esperado.

O leitor do servidor não verifica que o nonce recebido seja igual a
`IV_base || seq_no`; ele passa o nonce recebido ao AES-GCM. O cliente ainda deve
usar a construção indicada para interoperar com o protocolo descrito.

## 3. JSON carregado dentro do transporte

O plaintext de uma mensagem C2S é um objeto JSON UTF-8 sem delimitador próprio;
seu limite é o corpo do frame de transporte. O servidor lê `sender_id` e
`recipient_id`, e encaminha os demais campos sem interpretá-los:

| Ordem lógica | Campo JSON | Valor |
|---|---|---|
| 1 | `sender_id` | UUID textual do remetente. |
| 2 | `recipient_id` | UUID textual do destinatário. |
| 3 | `seq_no` | Contador E2E como string decimal sem sinal, para preservar os 64 bits em JSON. |
| 4 | `nonce` | Nonce E2E de 12 bytes codificado em Base64. |
| 5 | `ciphertext` | Frame E2E binário completo codificado em Base64, incluindo cabeçalho, ciphertext e tag. |

O servidor verifica que `sender_id` corresponde à sessão do socket. Para uma
mensagem comum, define/adiciona `control: false`, serializa o objeto JSON e o
envia ao destinatário dentro de um novo frame protegido pela chave S2C daquele
destinatário. Não decifra nem valida o conteúdo E2E de `ciphertext`.

O servidor não valida os tipos/formato de `seq_no`, `nonce` ou `ciphertext` no
JSON; a validação do contador do frame de transporte é separada.

### 3.1. Frame E2E binário contido em `ciphertext`

O cliente codifica os seguintes campos, sem prefixo de comprimento interno.
O tamanho é inferido do valor Base64 do envelope:

| Offset | Campo | Tamanho | Codificação |
|---:|---|---:|---|
| 0 | `nonce` | 12 bytes | `IV_base (4B) || seq_no (8B)`. |
| 12 | `sender_id` | 16 bytes | UUID raw, ordem de rede. |
| 28 | `recipient_id` | 16 bytes | UUID raw, ordem de rede. |
| 44 | `seq_no` | 8 bytes | Unsigned big-endian. |
| 52 | `ciphertext` | Variável | AES-128-GCM do plaintext UTF-8, máximo 4096 bytes. |
| Final | `tag` | 16 bytes | Tag GCM concatenada após o ciphertext. |

O menor frame E2E tem 68 bytes. O AAD é `sender_id (16B) || recipient_id
(16B) || seq_no (8B)`. Os campos `nonce` e `seq_no` também aparecem no envelope
JSON externo; o cliente receptor verifica que correspondam às cópias no frame
E2E. Os contadores E2E por peer não são os contadores do canal C2S/S2C.

## 4. Mensagens administrativas do servidor

As mensagens administrativas usam o mesmo frame binário S2C da seção 2. O
plaintext JSON tem os campos externos abaixo:

| Campo JSON | Valor |
|---|---|
| `sender_id` | String literal `server`. |
| `recipient_id` | String UUID do cliente destinatário. |
| `seq_no` | Contador S2C numérico. |
| `nonce` | Nonce codificado em Base64. |
| `control` | `true`. |
| `ciphertext` | Objeto JSON de controle, não string cifrada na camada E2E. |

O objeto `ciphertext` de controle tem `info` e `data`:

| `info` | `data` | Significado |
|---|---|---|
| `new_user` | `[client_id, pk_C_base64]` | Informa a chave pública X25519 de um cliente. |
| `user_exit` | `[client_id]` | Informa a desconexão de um cliente. |

Na entrada de um cliente, o servidor envia `new_user` ao cliente novo para cada
cliente já conectado e aos clientes existentes para informar o recém-chegado.
O código tenta enviar `user_exit` ao desconectar, mas não o entrega: `close_conn`
remove primeiro o cliente de `sessions`, e `broadcast` retorna quando o ID não
está mais nessa tabela. Portanto, clientes podem manter peers desconectados até
receberem um `new_user` com nova chave pública. O código não envia confirmação
administrativa explícita de registro.

## 5. Divergências entre as fontes

O código do servidor define os bytes atualmente aceitos, mas há diferenças que
impedem tratar o protocolo E2E do PDF como já implementado:

1. **Nomes dos campos do handshake:** o código usa `server_crt` e `signature`;
   o README documenta `server.crt` e `rsa_signature`.
2. **Identificador assinado:** o código assina `client_id` como UTF-8 (string de
   tamanho variável); o PDF exige UUID binário de 16 bytes no material assinado.
3. **Camadas criptográficas:** o handshake do código deriva chaves C2S/S2C
   cliente-servidor. O PDF exige também chaves E2E distintas por par de clientes,
   derivadas das chaves públicas dos peers.
4. **Frame E2E:** o servidor atual só lê frames de transporte C2S e não
   encaminha diretamente os bytes recebidos: decifra a camada de transporte,
   interpreta JSON e recifra o envelope pela sessão S2C do destinatário. Para
   compatibilidade, o cliente inclui o frame binário E2E completo em Base64 no
   campo JSON `ciphertext`; os bytes internos E2E continuam opacos ao servidor.
5. **Salt da derivação E2E:** cada conexão recebe um `salt_srv` diferente, e as
   mensagens `new_user` distribuem somente `client_id` e chave pública. A regra
   temporária escolhida é ordenar os IDs UUID raw lexicograficamente e derivar
   `salt_par = SHA256(id_A || id_B || pk_A || pk_B)[:16]`. Esse salt é usado
   somente no HKDF E2E. O servidor também usa `salt_srv` no HKDF do canal C2S/S2C,
   além de incluí-lo no material da assinatura.
6. **Nonce E2E:** o PDF requer `IV_base` de 4 bytes por direção, mas não define
   como os peers comunicam ou acordam esses valores. A decisão de implementação
   é o remetente sortear e manter o valor fixo na direção; o receptor aprende
   os 4 primeiros bytes do nonce após validar a primeira tag AES-GCM. Isso difere
   da tabela `peers` do PDF, que sorteia `IV_base_recv` independentemente.

Decisões de implementação: seguir os nomes e a assinatura que o servidor Python
realmente implementa; transportar o frame E2E opaco dentro do envelope JSON
protegido pelo canal C2S/S2C; e usar o `salt_par` descrito acima para as chaves
E2E. Essas escolhas priorizam compatibilidade com o servidor atual, mas são
temporárias e estão registradas em `DIVIDA_TECNICA.md`.

## Pontos para alinhamento futuro

1. Confirmar com o professor e com o outro integrante as regras temporárias de
   salt E2E e de encapsulamento do frame E2E.
2. Harmonizar os nomes dos campos e o material assinado entre o README, o PDF e
   o código do servidor.
