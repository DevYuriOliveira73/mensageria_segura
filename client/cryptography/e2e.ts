import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from 'node:crypto';

import {
  validarSeqNo,
  validarTamanho,
  validarTamanhoMaximo,
} from '../helpers/validadores.js';

const AES_KEY_LENGTH = 16;
const IV_BASE_LENGTH = 4;
const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;
const ID_LENGTH = 16;
const SEQ_LENGTH = 8;
export const MAX_PLAINTEXT_E2E = 4096;

export interface PeerState {
  keySend: Buffer;
  keyRecv: Buffer;
  seqSend: bigint;
  seqRecv: bigint;
  ivBaseSend: Buffer;
  ivBaseRecv: Buffer | null;
}

export interface E2EFrame {
  nonce: Buffer;
  senderId: Buffer;
  recipientId: Buffer;
  seqNo: bigint;
  ciphertext: Buffer;
  tag: Buffer;
}

export function criarEstadoPar(keySend: Buffer, keyRecv: Buffer): PeerState {
  validarTamanho(keySend, AES_KEY_LENGTH, 'Chave AES-128');
  validarTamanho(keyRecv, AES_KEY_LENGTH, 'Chave AES-128');
  return {
    keySend: Buffer.from(keySend),
    keyRecv: Buffer.from(keyRecv),
    seqSend: 0n,
    seqRecv: -1n,
    ivBaseSend: randomBytes(IV_BASE_LENGTH),
    ivBaseRecv: null,
  };
}

export function montarNonce(ivBase: Buffer, seqNo: bigint): Buffer {
  if (ivBase.length !== IV_BASE_LENGTH) {
    throw new Error('ivBase deve ter exatamente 4 bytes');
  }
  validarSeqNo(seqNo);

  const nonce = Buffer.alloc(NONCE_LENGTH);
  ivBase.copy(nonce, 0);
  nonce.writeBigUInt64BE(seqNo, IV_BASE_LENGTH);
  return nonce;
}

export function validarNonce(
  nonce: Buffer,
  seqNo: bigint,
  peer: Pick<PeerState, 'ivBaseRecv' | 'seqRecv'>,
): Buffer {
  validarSeqNo(seqNo);
  if (nonce.length !== NONCE_LENGTH) {
    throw new Error('nonce deve ter exatamente 12 bytes');
  }
  if (nonce.readBigUInt64BE(IV_BASE_LENGTH) !== seqNo) {
    throw new Error('O seq_no no nonce não corresponde ao cabeçalho');
  }
  if (peer.ivBaseRecv !== null && !nonce.subarray(0, IV_BASE_LENGTH).equals(peer.ivBaseRecv)) {
    throw new Error('ivBase recebido mudou durante a sessão');
  }
  if (seqNo <= peer.seqRecv) {
    throw new Error('seq_no repetido ou fora de ordem');
  }

  return Buffer.from(nonce.subarray(0, IV_BASE_LENGTH));
}

export function encryptMessage(
  peer: PeerState,
  plaintext: Buffer,
  senderId: Buffer,
  recipientId: Buffer,
): E2EFrame {
  validarTamanhoMaximo(plaintext, MAX_PLAINTEXT_E2E, 'Plaintext E2E');
  validarTamanho(senderId, ID_LENGTH, 'senderId');
  validarTamanho(recipientId, ID_LENGTH, 'recipientId');
  validarSeqNo(peer.seqSend);

  const seqNo = peer.seqSend;
  const nonce = montarNonce(peer.ivBaseSend, seqNo);
  const cipher = createCipheriv('aes-128-gcm', peer.keySend, nonce, {
    authTagLength: TAG_LENGTH,
  });
  cipher.setAAD(montarAad(senderId, recipientId, seqNo));

  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  peer.seqSend += 1n;

  return {
    nonce,
    senderId: Buffer.from(senderId),
    recipientId: Buffer.from(recipientId),
    seqNo,
    ciphertext,
    tag,
  };
}

export function decryptMessage(peer: PeerState, frame: E2EFrame): Buffer {
  validarTamanho(frame.senderId, ID_LENGTH, 'senderId');
  validarTamanho(frame.recipientId, ID_LENGTH, 'recipientId');
  validarTamanhoMaximo(frame.ciphertext, MAX_PLAINTEXT_E2E, 'Plaintext E2E');
  if (frame.tag.length !== TAG_LENGTH) {
    throw new Error('tag AES-GCM deve ter exatamente 16 bytes');
  }

  const candidateIvBase = validarNonce(frame.nonce, frame.seqNo, peer);
  const decipher = createDecipheriv('aes-128-gcm', peer.keyRecv, frame.nonce, {
    authTagLength: TAG_LENGTH,
  });
  decipher.setAAD(montarAad(frame.senderId, frame.recipientId, frame.seqNo));
  decipher.setAuthTag(frame.tag);

  const plaintext = Buffer.concat([
    decipher.update(frame.ciphertext),
    decipher.final(),
  ]);

  // O estado do peer só muda após a validação da tag GCM.
  if (peer.ivBaseRecv === null) {
    peer.ivBaseRecv = Buffer.from(candidateIvBase);
  }
  peer.seqRecv = frame.seqNo;
  return plaintext;
}

export function codificarFrameE2E(frame: E2EFrame): Buffer {
  validarTamanho(frame.senderId, ID_LENGTH, 'senderId');
  validarTamanho(frame.recipientId, ID_LENGTH, 'recipientId');
  if (frame.nonce.length !== NONCE_LENGTH || frame.tag.length !== TAG_LENGTH) {
    throw new Error('Nonce ou tag com tamanho inválido');
  }
  validarSeqNo(frame.seqNo);

  const seqBytes = Buffer.alloc(SEQ_LENGTH);
  seqBytes.writeBigUInt64BE(frame.seqNo);
  return Buffer.concat([
    frame.nonce,
    frame.senderId,
    frame.recipientId,
    seqBytes,
    frame.ciphertext,
    frame.tag,
  ]);
}

export function decodificarFrameE2E(bytes: Buffer): E2EFrame {
  const tamanhoCabecalho = NONCE_LENGTH + ID_LENGTH * 2 + SEQ_LENGTH;
  const tamanhoMinimo = tamanhoCabecalho + TAG_LENGTH;
  if (bytes.length < tamanhoMinimo) {
    throw new Error('Frame E2E truncado');
  }

  const nonce = Buffer.from(bytes.subarray(0, NONCE_LENGTH));
  const senderId = Buffer.from(bytes.subarray(NONCE_LENGTH, NONCE_LENGTH + ID_LENGTH));
  const inicioRecipient = NONCE_LENGTH + ID_LENGTH;
  const recipientId = Buffer.from(bytes.subarray(inicioRecipient, inicioRecipient + ID_LENGTH));
  const inicioSeq = inicioRecipient + ID_LENGTH;
  const seqNo = bytes.readBigUInt64BE(inicioSeq);
  const inicioCiphertext = inicioSeq + SEQ_LENGTH;
  const inicioTag = bytes.length - TAG_LENGTH;
  const ciphertext = Buffer.from(bytes.subarray(inicioCiphertext, inicioTag));
  const tag = Buffer.from(bytes.subarray(inicioTag));
  validarTamanhoMaximo(ciphertext, MAX_PLAINTEXT_E2E, 'Plaintext E2E');

  return { nonce, senderId, recipientId, seqNo, ciphertext, tag };
}

function montarAad(senderId: Buffer, recipientId: Buffer, seqNo: bigint): Buffer {
  const seqBytes = Buffer.alloc(SEQ_LENGTH);
  seqBytes.writeBigUInt64BE(seqNo);
  return Buffer.concat([senderId, recipientId, seqBytes]);
}
