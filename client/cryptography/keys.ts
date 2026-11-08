import {
  createHash,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  type KeyObject,
} from 'node:crypto';

import { validarTamanho } from '../helpers/validadores.js';

const TAMANHO_CHAVE_RAW = 32;
const TAMANHO_ID = 16;
const TAMANHO_CHAVE_AES = 16;
const PREFIXO_SPKI_X25519 = Buffer.from('302a300506032b656e032100', 'hex');

export type DirecaoE2E = 'A2B' | 'B2A';

export interface ParX25519 {
  privateKey: KeyObject;
  publicKey: Buffer;
}

export interface ChavesPar {
  keySend: Buffer;
  keyRecv: Buffer;
  sendLabel: DirecaoE2E;
  receiveLabel: DirecaoE2E;
}

export interface ChavesCanal {
  c2s: Buffer;
  s2c: Buffer;
}

export function gerarParX25519(): ParX25519 {
  const { privateKey, publicKey } = generateKeyPairSync('x25519');
  return { privateKey, publicKey: toRaw(publicKey) };
}

export function toRaw(publicKey: KeyObject): Buffer {
  const der = publicKey.export({ format: 'der', type: 'spki' });
  if (
    der.length !== PREFIXO_SPKI_X25519.length + TAMANHO_CHAVE_RAW ||
    !der.subarray(0, PREFIXO_SPKI_X25519.length).equals(PREFIXO_SPKI_X25519)
  ) {
    throw new Error('Chave pública não é X25519 no formato SPKI esperado');
  }
  return Buffer.from(der.subarray(PREFIXO_SPKI_X25519.length));
}

export function fromRaw(publicKey: Buffer): KeyObject {
  if (publicKey.length !== TAMANHO_CHAVE_RAW) {
    throw new Error('Chave pública X25519 raw deve ter exatamente 32 bytes');
  }
  return createPublicKey({
    key: Buffer.concat([PREFIXO_SPKI_X25519, publicKey]),
    format: 'der',
    type: 'spki',
  });
}

export function segredoCompartilhado(privateKey: KeyObject, peerPublicKey: Buffer): Buffer {
  return diffieHellman({ privateKey, publicKey: fromRaw(peerPublicKey) });
}

export function uuidParaBytes(clientId: string): Buffer {
  if (!/^[\da-f]{8}-(?:[\da-f]{4}-){3}[\da-f]{12}$/i.test(clientId)) {
    throw new Error('client_id deve ser um UUID textual válido');
  }
  return Buffer.from(clientId.replaceAll('-', ''), 'hex');
}

export function saltDoPar(
  localId: Buffer,
  localPublicKey: Buffer,
  peerId: Buffer,
  peerPublicKey: Buffer,
): Buffer {
  validarTamanho(localId, TAMANHO_ID, 'ID local');
  validarTamanho(peerId, TAMANHO_ID, 'ID do peer');
  validarTamanho(localPublicKey, TAMANHO_CHAVE_RAW, 'Chave pública local');
  validarTamanho(peerPublicKey, TAMANHO_CHAVE_RAW, 'Chave pública do peer');

  const comparacao = Buffer.compare(localId, peerId);
  if (comparacao === 0) {
    throw new Error('Dois peers não podem ter o mesmo client_id');
  }

  const [idA, idB, chaveA, chaveB] = comparacao < 0
    ? [localId, peerId, localPublicKey, peerPublicKey]
    : [peerId, localId, peerPublicKey, localPublicKey];
  return createHash('sha256')
    .update(Buffer.concat([idA, idB, chaveA, chaveB]))
    .digest()
    .subarray(0, 16);
}

export function derivarChavesPar(
  localId: Buffer,
  localPublicKey: Buffer,
  peerId: Buffer,
  peerPublicKey: Buffer,
  sharedSecret: Buffer,
): ChavesPar {
  const salt = saltDoPar(localId, localPublicKey, peerId, peerPublicKey);
  const localIsA = Buffer.compare(localId, peerId) < 0;
  const keyA2B = derivarChave(sharedSecret, salt, 'A2B');
  const keyB2A = derivarChave(sharedSecret, salt, 'B2A');

  return localIsA
    ? { keySend: keyA2B, keyRecv: keyB2A, sendLabel: 'A2B', receiveLabel: 'B2A' }
    : { keySend: keyB2A, keyRecv: keyA2B, sendLabel: 'B2A', receiveLabel: 'A2B' };
}

export function derivarChavesCanal(sharedSecret: Buffer, salt: Buffer): ChavesCanal {
  return {
    c2s: derivarChave(sharedSecret, salt, 'c2s'),
    s2c: derivarChave(sharedSecret, salt, 's2c'),
  };
}

function derivarChave(sharedSecret: Buffer, salt: Buffer, info: string): Buffer {
  return Buffer.from(
    hkdfSync('sha256', sharedSecret, salt, Buffer.from(info, 'ascii'), TAMANHO_CHAVE_AES),
  );
}
