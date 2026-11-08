import { isUtf8 } from 'node:buffer';
import type { KeyObject } from 'node:crypto';

import { CanalSeguro } from '../communication/canal.js';
import {
  analisarEnvelope,
  criarEnvelopeMensagem,
  decodificarChavePublica,
  serializarEnvelope,
  uuidEmBytes,
  type ControleEnvelope,
  type MensagemEnvelope,
} from '../communication/envelope.js';
import {
  codificarFrameE2E,
  criarEstadoPar,
  decodificarFrameE2E,
  decryptMessage,
  encryptMessage,
  MAX_PLAINTEXT_E2E,
  type PeerState,
} from '../cryptography/e2e.js';
import { derivarChavesPar, segredoCompartilhado } from '../cryptography/keys.js';

export interface Peer {
  publicKey: Buffer;
  state: PeerState;
}

export async function receberMensagens(
  canal: CanalSeguro,
  clientId: string,
  privateKey: KeyObject,
  publicKey: Buffer,
  peers: Map<string, Peer>,
  encerrando: () => boolean,
): Promise<void> {
  try {
    while (true) {
      const json = await canal.receberJson();
      if (json === null) {
        if (!encerrando()) console.log('\nServidor encerrou a conexão.');
        return;
      }

      const envelope = analisarEnvelope(json);
      if (envelope.recipientId.toLowerCase() !== clientId.toLowerCase()) {
        throw new Error('Envelope recebido tem destinatário diferente deste cliente');
      }

      if (envelope.kind === 'control') {
        tratarControle(envelope, clientId, privateKey, publicKey, peers);
        continue;
      }

      try {
        tratarMensagem(envelope, clientId, peers);
      } catch (error) {
        console.error(
          `Mensagem de ${envelope.senderId} rejeitada: ${mensagemErro(error)}`,
        );
      }
    }
  } catch (error) {
    if (!encerrando()) {
      console.error(`Canal encerrado: ${mensagemErro(error)}`);
      process.exitCode = 1;
    }
  } finally {
    process.stdin.destroy();
  }
}

function tratarControle(
  envelope: ControleEnvelope,
  clientId: string,
  privateKey: KeyObject,
  publicKey: Buffer,
  peers: Map<string, Peer>,
): void {
  if (envelope.info === 'user_exit') {
    const departedId = envelope.data[0].toLowerCase();
    peers.delete(departedId);
    console.log(`\n${departedId} desconectou.`);
    return;
  }

  const peerId = envelope.data[0].toLowerCase();
  if (peerId === clientId.toLowerCase()) {
    throw new Error('Servidor anunciou este cliente como um peer remoto');
  }
  const peerPublicKey = decodificarChavePublica(envelope.data[1]);
  const previousPeer = peers.get(peerId);
  if (previousPeer?.publicKey.equals(peerPublicKey)) {
    console.error(`new_user repetido com a mesma chave para ${peerId}; estado mantido.`);
    return;
  }

  const sharedSecret = segredoCompartilhado(privateKey, peerPublicKey);
  const pairKeys = derivarChavesPar(
    uuidEmBytes(clientId),
    publicKey,
    uuidEmBytes(peerId),
    peerPublicKey,
    sharedSecret,
  );
  peers.set(peerId, {
    publicKey: Buffer.from(peerPublicKey),
    state: criarEstadoPar(pairKeys.keySend, pairKeys.keyRecv),
  });
  console.log(`\n${previousPeer ? 'Chave de peer atualizada' : 'Peer disponível'}: ${peerId}`);
}

function tratarMensagem(
  envelope: MensagemEnvelope,
  clientId: string,
  peers: Map<string, Peer>,
): void {
  const peerId = envelope.senderId.toLowerCase();
  const peer = peers.get(peerId);
  if (!peer) {
    throw new Error('Remetente ainda não está registrado como peer');
  }

  const frame = decodificarFrameE2E(envelope.ciphertext);
  if (frame.seqNo !== envelope.seqNo) {
    throw new Error('seq_no do envelope não corresponde ao frame E2E');
  }
  if (!frame.nonce.equals(envelope.nonce)) {
    throw new Error('nonce do envelope não corresponde ao frame E2E');
  }
  if (!frame.senderId.equals(uuidEmBytes(envelope.senderId))) {
    throw new Error('sender_id do envelope não corresponde ao frame E2E');
  }
  if (!frame.recipientId.equals(uuidEmBytes(clientId))) {
    throw new Error('recipient_id do frame E2E não corresponde ao cliente');
  }

  const plaintext = decryptMessage(peer.state, frame);
  if (!isUtf8(plaintext)) {
    throw new Error('Mensagem E2E não é UTF-8 válido');
  }
  console.log(`\n[${envelope.senderId}] ${plaintext.toString('utf8')}`);
}

export async function processarComando(
  command: string,
  canal: CanalSeguro,
  clientId: string,
  peers: Map<string, Peer>,
): Promise<void> {
  if (command === '/peers') {
    const ids = [...peers.keys()];
    console.log(ids.length === 0 ? 'Nenhum peer conectado.' : ids.join('\n'));
    return;
  }
  if (command === '/help') {
    console.log('Comandos: /peers, /msg <client_id> <mensagem>, /quit');
    return;
  }

  const match = /^\/msg\s+(\S+)\s+([\s\S]*)$/.exec(command);
  if (!match) {
    throw new Error('Comando inválido. Use /msg <client_id> <mensagem>.');
  }

  const recipientId = match[1].toLowerCase();
  const peer = peers.get(recipientId);
  if (!peer) {
    throw new Error(`Peer ${recipientId} não está conectado`);
  }
  const plaintext = Buffer.from(match[2], 'utf8');
  if (plaintext.length > MAX_PLAINTEXT_E2E) {
    throw new Error(`Mensagem excede o limite de ${MAX_PLAINTEXT_E2E} bytes`);
  }

  const frame = encryptMessage(
    peer.state,
    plaintext,
    uuidEmBytes(clientId),
    uuidEmBytes(recipientId),
  );
  const encodedFrame = codificarFrameE2E(frame);
  const envelope = criarEnvelopeMensagem(
    clientId,
    recipientId,
    frame.seqNo,
    frame.nonce,
    encodedFrame,
  );
  await canal.enviarJson(serializarEnvelope(envelope));
}

function mensagemErro(error: unknown): string {
  return error instanceof Error ? error.message : 'erro desconhecido';
}
