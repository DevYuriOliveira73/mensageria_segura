# Protocolo de Comunicação

## 1. Handshake e estabelecimento de chaves

O processo de handshake é responsável por estabelecer um segredo compartilhado entre cliente e servidor, derivar as chaves de comunicação e inicializar a sessão criptográfica.

### 1.1. Estabelecimento da conexão

1. O cliente estabelece uma conexão TCP com o servidor.
2. O cliente envia sua chave pública X25519 em um pacote JSON, seguindo o formato:

```json
{
    "client_id": "...",
    "pkey": "..."
}
```

3. O servidor responde com:

```json
{
    "pk_S": "...",
    "server.crt": "...",
    "rsa_signature": "...",
    "salt_srv": "..."
}
```

Caso o pacote recebido seja inválido, a conexão será encerrada.

### 1.2. Codificação dos dados

Todos os campos que representam dados binários devem ser codificados em Base64 antes de serem inseridos no JSON:

- Chaves públicas;
- Assinatura RSA;
- Salt;
- Certificado.

### 1.3. Derivação das chaves

4. Cliente e servidor utilizam suas respectivas chaves privadas e as chaves públicas recebidas para chegar ao mesmo segredo compartilhado.
5. O segredo compartilhado é utilizado para derivar uma chave AES-128.
6. São derivadas duas chaves independentes, uma para cada direção da comunicação:
   - Cliente → Servidor;
   - Servidor → Cliente.

Após o estabelecimento das chaves, ambos passam a utilizá-las para criptografar e descriptografar as mensagens trocadas.

### 1.4. Distribuição das chaves públicas dos clientes

A chave pública X25519 de cada cliente será armazenada internamente pelo servidor.

O servidor ficará responsável por encaminhar essas chaves públicas para todos os clientes conectados, bem como para aqueles que se conectarem posteriormente.

Consequentemente, o cliente deverá implementar operações paralelas de leitura e escrita no socket, permitindo receber e enviar mensagens simultaneamente, sem bloquear uma operação enquanto a outra estiver em andamento.

---

## 2. Troca de mensagens

Após a conclusão do handshake, toda comunicação entre cliente e servidor deverá utilizar pacotes binários, seguindo uma estrutura fixa.

### 2.1. Estrutura do pacote enviado pelo cliente

O cliente envia os seguintes bytes ao servidor:

```text
tcp_frame_len (4B)
+ nonce          (12B)
+ seq_no          (8B)
+ ciphertext      (+...)
+ tag             (16B)
```

<text>**Prefixo de tamanho fixo: 24 bytes.** Considerando também a tag de 16 bytes, o overhead fixo total é de 40 bytes, sem contar o ciphertext.</text>

Os campos são organizados da seguinte maneira:

| Campo | Tamanho | Descrição |
|---|---:|---|
| `tcp_frame_len` | 4 bytes | Tamanho do pacote que se segue. |
| `nonce` | 12 bytes | Nonce utilizado pelo AES-GCM. |
| `seq_no` | 8 bytes | Contador sequencial da mensagem. |
| `ciphertext` | Variável | Conteúdo criptografado. |
| `tag` | 16 bytes | Tag do AES-GCM, utilizada para verificar a integridade e autenticidade. |

### 2.2. Geração do nonce

O nonce será construído a partir da concatenação de dois campos:

```text
nonce = IV_base (4B) || seq_no (8B)
```

- `IV_base`: gerado uma única vez por sessão.
- `seq_no`: contador sequencial da comunicação.

Essa estrutura garante a geração de nonces distintos para cada mensagem, desde que o contador não seja reutilizado com a mesma chave.

### 2.3. Autenticação dos dados (AAD)

O AAD utilizado pelo AES-GCM será composto por:

```text
AAD = sender_id (16B) || seq_no (8B)
```

O servidor deverá associar o `sender_id` ao socket correspondente à sessão e validar essa associação antes de aceitar a mensagem.

### 2.4. Validação do contador sequencial

O servidor armazenará o próximo `seq_no` esperado para cada sessão.

Ao receber uma mensagem, deverá verificar se o contador recebido corresponde ao valor esperado.

Após cada envio ou recebimento bem-sucedido, cliente e servidor deverão incrementar seus respectivos contadores:

- `seq_send`: contador de envio.
- `seq_recv`: contador de recebimento.

### 2.5. Processamento pelo servidor

Após receber o pacote, o servidor utilizará os dados recebidos para descriptografar o ciphertext.

O plaintext obtido deverá conter os seguintes campos:

```json
{
    "sender_id": "...",
    "recipient_id": "...",
    "seq_no": "...",
    "nonce": "...",
    "ciphertext": "..."
}
```

O servidor não deverá alterar os dados da mensagem original, apenas encaminhá-los ao destinatário correspondente.

---

## 3. Comunicação do servidor para os clientes

Ao encaminhar uma mensagem, o servidor deverá utilizar a camada de criptografia Cliente-Servidor, seguindo a mesma estrutura binária de pacotes:

```text
tcp_frame_len (4B)
+ nonce          (12B)
+ seq_no          (8B)
+ ciphertext      (+...)
+ tag             (16B)
```

### 3.1. Autenticação do servidor (AAD)

O AAD utilizado pelo servidor será composto por:

```text
AAD = b'server' || seq_no (8B)
```

Dessa forma, o cliente deverá armazenar o contador `seq_no` recebido do servidor para validar os próximos pacotes.

A cada envio ou recebimento bem-sucedido, os respectivos contadores deverão ser incrementados.

---

## 4. Configuração do AES-GCM

A inicialização do AES-GCM deverá utilizar os seguintes parâmetros:

| Parâmetro | Valor |
|---|---|
| Chave | Chave correspondente à direção da comunicação. |
| Modo | AES-GCM. |
| Nonce | `IV_base (4B) || seq_no (8B)`. |
| AAD | Dados de autenticação definidos para cada direção. |

O AAD será diferente dependendo da origem da mensagem:

**Cliente → Servidor**
```text
sender_id (16B) || seq_no (8B)
```

**Servidor → Cliente**
```text
b'server' || seq_no (8B)
```

---

## 5. Mensagens de controle

O servidor será responsável por inserir um campo adicional nas mensagens encaminhadas, indicando se o conteúdo representa uma mensagem de controle.

Campo adicionado:

```json
{
    "control": true
}
```

O campo poderá assumir dois valores:

- `true`: indica uma mensagem de controle do servidor. Nesse caso, o conteúdo do campo `ciphertext` estará sem criptografia na camada de aplicação.
- `false`: indica uma mensagem comum, cujo conteúdo deverá ser tratado normalmente.

### 5.1. Estrutura das mensagens de controle

Uma mensagem de controle, armazenada no campo `ciphertext`, deverá seguir a estrutura:

```json
{
    "info": "tipo_de_mensagem",
    "data": []
}
```

O campo `info` identifica o tipo de mensagem de controle, enquanto `data` contém os dados associados à operação.

### 5.2. Tipos de mensagens de controle

#### 5.2.1. `new_user`

Notifica os clientes sobre a entrada de um novo usuário.

```json
{
    "info": "new_user",
    "data": [
        "client_id",
        "pk_C"
    ]
}
```

| Campo | Descrição |
|---|---|
| `client_id` | Identificador do novo cliente. |
| `pk_C` | Chave pública X25519 do novo cliente. |

- Quantidade de elementos em `data`: **2**.

#### 5.2.2. `user_exit`

Notifica os clientes sobre a saída de um usuário.

```json
{
    "info": "user_exit",
    "data": [
        "client_id"
    ]
}
```

| Campo | Descrição |
|---|---|
| `client_id` | Identificador do cliente que saiu. |

- Quantidade de elementos em `data`: **1**.