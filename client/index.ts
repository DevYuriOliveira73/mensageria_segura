import { isUtf8 } from 'node:buffer';
import type { KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createConnection, type Socket } from 'node:net';

import { CanalSeguro } from './canal.js';
import {
  analisarEnvelope,
  criarEnvelopeMensagem,
  decodificarChavePublica,
  serializarEnvelope,
  uuidEmBytes,
  type ControleEnvelope,
  type MensagemEnvelope,
} from './envelope.js';
import {
  codificarFrameE2E,
  criarEstadoPar,
  decodificarFrameE2E,
  decryptMessage,
  encryptMessage,
  MAX_PLAINTEXT_E2E,
  type PeerState,
} from './e2e.js';
import { LeitorTcp } from './framing.js';
import { executarHandshake } from './handshake.js';
import { derivarChavesPar, segredoCompartilhado } from './keys.js';

const HOST_PADRAO = '127.0.0.1';
const PORTA_PADRAO = 9000;
const CERTIFICADO_PINADO = new URL('../server/src/keys/certificado.crt', import.meta.url);

interface Peer {
  publicKey: Buffer;
  state: PeerState;
}

async function main(): Promise<void> {
  const host = process.env.MENSAGERIA_HOST ?? HOST_PADRAO;
  const port = parsePort(process.env.MENSAGERIA_PORT);
  const socket = await conectar(host, port);

  try {
    const leitor = new LeitorTcp(socket);
    const certificado = readFileSync(CERTIFICADO_PINADO);
    const sessao = await executarHandshake(socket, leitor, certificado);
    const canal = new CanalSeguro(
      socket,
      leitor,
      uuidEmBytes(sessao.clientId),
      sessao.channelKeys.c2s,
      sessao.channelKeys.s2c,
    );
    const peers = new Map<string, Peer>();

    console.log(`Conectado como ${sessao.clientId}`);
    console.log('Comandos: /peers, /msg <client_id> <mensagem>, /quit');
    let encerrando = false;
    const recebimento = receberMensagens(
      canal,
      sessao.clientId,
      sessao.keyPair.privateKey,
      sessao.keyPair.publicKey,
      peers,
      () => encerrando,
    );

    try {
      process.stdout.write('> ');
      for await (const line of linhasDeEntrada()) {
        const command = line.trim();
        if (command.length === 0) {
          process.stdout.write('> ');
          continue;
        }
        if (command === '/quit') break;
        try {
          await processarComando(command, canal, sessao.clientId, peers);
        } catch (error) {
          console.error(`Comando rejeitado: ${mensagemErro(error)}`);
          if (socket.destroyed) throw error;
        }
        process.stdout.write('> ');
      }
    } finally {
      encerrando = true;
      socket.end();
    }

    await recebimento;
  } finally {
    if (!socket.destroyed) socket.destroy();
  }
}

async function receberMensagens(
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

async function processarComando(
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

async function conectar(host: string, port: number): Promise<Socket> {
  const socket = createConnection({ host, port });
  await new Promise<void>((resolve, reject) => {
    const onConnect = (): void => {
      socket.off('error', onError);
      resolve();
    };
    const onError = (error: Error): void => {
      socket.off('connect', onConnect);
      reject(error);
    };
    socket.once('connect', onConnect);
    socket.once('error', onError);
  });
  return socket;
}

async function* linhasDeEntrada(): AsyncGenerator<string> {
  let buffer = Buffer.alloc(0);
  for await (const chunk of process.stdin) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    buffer = Buffer.concat([buffer, bytes]);
    let newline = buffer.indexOf(0x0a);
    while (newline >= 0) {
      let line = buffer.subarray(0, newline);
      if (line.at(-1) === 0x0d) line = line.subarray(0, line.length - 1);
      yield line.toString('utf8');
      buffer = buffer.subarray(newline + 1);
      newline = buffer.indexOf(0x0a);
    }
  }
  if (buffer.length > 0) yield buffer.toString('utf8');
}

function parsePort(value: string | undefined): number {
  if (value === undefined) return PORTA_PADRAO;
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('MENSAGERIA_PORT deve ser uma porta entre 1 e 65535');
  }
  return port;
}

function mensagemErro(error: unknown): string {
  return error instanceof Error ? error.message : 'erro desconhecido';
}

main().catch((error: unknown) => {
  console.error(`Falha no cliente: ${mensagemErro(error)}`);
  process.exitCode = 1;
});