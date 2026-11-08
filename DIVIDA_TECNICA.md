# Dívida técnica

## IV_base aprendido do nonce do frame (solução não prevista no enunciado)

- **Contexto:** O enunciado manda cada direção ter um `IV_base` aleatório de 4
  bytes, mas não diz como o receptor o conhece. A tabela `peers` inicializa
  `IV_base_recv` como `random(4B)`, o que não bateria com o valor sorteado pelo
  remetente.
- **O que foi feito:** O remetente sorteia e mantém o `ivBaseSend` fixo durante
  a sessão. O receptor aprende o IV a partir do nonce do frame e só o fixa
  depois que a primeira tag AES-GCM valida. A montagem e validação estão nas
  funções `montarNonce` e `validarNonce` em `client/e2e.ts`.
- **Por que é aceitável por ora:** O nonce já viaja em claro no frame. A
  unicidade do par (chave, nonce) vem das chaves distintas por direção e por
  sessão e do `seq_no` estritamente crescente; portanto, o `IV_base` aleatório
  é defesa em profundidade, não a base da segurança.
- **Por que é uma dívida:** A regra foge da descrição literal do enunciado
  (`IV_base_recv` aleatório local), não foi confirmada com o professor nem com
  o autor do outro cliente e depende de o outro cliente manter o `IV_base`
  constante por direção.
- **Como resolver depois:** Confirmar a regra com o professor e com quem
  implementa o outro cliente. Se o protocolo fixar uma regra (por exemplo,
  `IV_base` derivado por HKDF-Expand com `info="IV_A2B"`/`"IV_B2A"` e `L=4`,
  ou a constante de direção `0x00000000`/`0x00000001`), trocar somente as
  funções de nonce em `client/e2e.ts` e os testes.
- **Status:** pendente.

## Salt E2E de par derivado de IDs e chaves públicas

- **Contexto:** O PDF sugere usar `salt_srv` no HKDF E2E, mas o servidor gera um
  salt diferente por conexão e não o inclui nas mensagens `new_user`. Assim,
  dois clientes não conseguem obter o mesmo salt E2E usando esse valor.
- **O que foi feito:** Para derivar as chaves E2E, ordenar os IDs UUID raw de
  16 bytes lexicograficamente como `id_A` e `id_B`, então calcular
  `salt_par = SHA256(id_A || id_B || pk_A || pk_B)[:16]`, com as chaves X25519
  públicas raw de 32 bytes na mesma ordem. Usar `salt_par` e o segredo ECDH como
  IKM em HKDF-SHA256; expandir com `A2B` e `B2A`, 16 bytes cada. O menor ID
  envia com `A2B` e recebe com `B2A`; o maior faz o inverso.
- **Por que funciona:** Os dois peers conhecem os mesmos IDs e chaves públicas,
  e os ordenam da mesma forma. O salt não é secreto; o segredo é o resultado
  ECDH. Chaves X25519 efêmeras novas tornam o salt diferente em reconexões.
- **Por que é uma dívida:** O PDF prevê salt gerado pelo servidor. Esta regra
  temporária precisa ser implementada identicamente por todos os clientes,
  inclusive o cliente do outro integrante.
- **Como resolver depois:** Confirmar a regra com o professor e com o outro
  integrante. Se o servidor distribuir o salt de sessão de cada cliente em
  `new_user` e na lista de peers, substituir a função `saltDoPar` por
  `SHA256(salt_do_id_A || salt_do_id_B)[:16]` e atualizar os vetores de teste.
- **Status:** pendente.

## Transporte E2E encapsulado no envelope do servidor

- **Contexto:** O PDF descreve um frame E2E binário, mas o servidor atual espera
  um frame de transporte C2S com JSON, lê esse JSON e reencaminha-o em um novo
  frame S2C. Não é compatível enviar o frame E2E diretamente pelo socket.
- **O que foi feito:** Seguir o fluxo implementado pelo servidor sem alterar
  `server/`: o cliente protegerá o envelope JSON no canal C2S/S2C e carregará
  nele o frame E2E opaco. O servidor continuará sem conhecer as chaves E2E e
  sem decifrar o conteúdo E2E.
- **Por que é aceitável por ora:** É o formato que o servidor atual aceita e
  permite manter o payload E2E opaco para o relay.
- **Por que é uma dívida:** O servidor termina e recria o frame de transporte;
  portanto, não encaminha diretamente os bytes do frame E2E como a descrição
  literal do PDF sugere.
- **Como resolver depois:** Alinhar com o professor e com o autor do servidor
  se o formato encapsulado é aceito ou se o servidor deve oferecer um modo de
  relay binário direto.
- **Status:** pendente.

## Handshake compatível com a implementação Python

- **Contexto:** O README descreve campos `server.crt` e `rsa_signature`, e o
  PDF define `client_id` binário de 16 bytes no material da assinatura. O código
  Python envia `server_crt` e `signature`, e assina o UUID como texto UTF-8.
- **O que foi feito:** Para interoperabilidade, o cliente usará os nomes e o
  material de assinatura do código Python: `server_crt`, `signature` e
  `pk_S_raw || pk_C_raw || client_id_utf8 || salt_srv`.
- **Por que é aceitável por ora:** É a assinatura produzida e o formato de
  resposta realmente enviados pelo servidor atual.
- **Por que é uma dívida:** Difere dos nomes do README e da codificação de
  `client_id` especificada no PDF.
- **Como resolver depois:** Atualizar servidor, documentação e cliente juntos
  para uma única codificação acordada; manter testes de assinatura para a
  representação escolhida.
- **Status:** pendente.

## salt_srv do handshake em HKDF

- **Contexto:** O servidor atual usa `salt_srv` tanto no material assinado pelo
  RSA-PSS quanto para derivar as chaves do canal de transporte C2S/S2C. A regra
  temporária de `salt_par` aplica-se somente ao HKDF E2E entre peers.
- **O que foi feito:** Não usar `salt_srv` para derivação das chaves E2E; manter
  seu uso no handshake e na derivação do canal cliente-servidor conforme o
  código Python.
- **Por que é uma dívida:** A descrição recebida de que `salt_srv` seria usado
  “só na assinatura” não corresponde ao código do servidor para o canal externo.
- **Como resolver depois:** Manter separados os salts de handshake/transporte e
  de par E2E na especificação final, e alinhar a redação com o professor.
- **Status:** pendente.

## `user_exit` não chega aos clientes no servidor atual

- **Contexto:** O servidor remove o cliente desconectado de `sessions` em
  `close_conn` e depois tenta chamar `broadcast('user_exit', client_id)`.
  `broadcast` retorna imediatamente quando o ID não está mais em `sessions`.
- **O que foi feito:** O cliente processa `user_exit` quando recebido e também
  aceita uma nova chave pública `new_user` para um peer já conhecido como uma
  nova sessão, recriando suas chaves e contadores E2E.
- **Por que é uma dívida:** Enquanto o servidor mantiver esse fluxo, os clientes
  podem exibir peers offline como conectados e não têm confirmação de entrega
  para mensagens encaminhadas a destinatários ausentes.
- **Como resolver depois:** Ajustar a ordem/contrato de `close_conn` e
  `broadcast` no servidor ou introduzir uma notificação que não dependa de a
  sessão removida continuar na tabela. A pasta `server/` permanece fora do
  escopo deste cliente.
- **Status:** pendente.
