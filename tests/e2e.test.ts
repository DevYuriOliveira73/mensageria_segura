import assert from 'node:assert/strict';
import test from 'node:test';

import {
  codificarFrameE2E,
  criarEstadoPar,
  decodificarFrameE2E,
  decryptMessage,
  encryptMessage,
  type PeerState,
} from '../client/cryptography/e2e.js';

const keyA2B = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
const keyB2A = Buffer.from('101112131415161718191a1b1c1d1e1f', 'hex');
const ivA2B = Buffer.from('a1a2a3a4', 'hex');
const ivB2A = Buffer.from('b1b2b3b4', 'hex');
const idA = Buffer.from('00000000000040008000000000000001', 'hex');
const idB = Buffer.from('00000000000040008000000000000002', 'hex');

function createPeer(keySend: Buffer, keyRecv: Buffer, ivBaseSend: Buffer): PeerState {
  const peer = criarEstadoPar(keySend, keyRecv);
  peer.ivBaseSend = Buffer.from(ivBaseSend);
  return peer;
}

test('dois peers trocam frames e aprendem os IVs no primeiro frame válido', () => {
  const peerA = createPeer(keyA2B, keyB2A, ivA2B);
  const peerB = createPeer(keyB2A, keyA2B, ivB2A);

  const first = encryptMessage(peerA, Buffer.from('A para B'), idA, idB);
  assert.equal(decryptMessage(peerB, first).toString(), 'A para B');
  assert.deepEqual(peerB.ivBaseRecv, ivA2B);
  assert.equal(peerB.seqRecv, 0n);

  const second = encryptMessage(peerA, Buffer.from('A para B novamente'), idA, idB);
  assert.equal(decryptMessage(peerB, second).toString(), 'A para B novamente');
  assert.equal(peerB.seqRecv, 1n);

  const reply = encryptMessage(peerB, Buffer.from('B para A'), idB, idA);
  assert.equal(decryptMessage(peerA, reply).toString(), 'B para A');
  assert.deepEqual(peerA.ivBaseRecv, ivB2A);
  assert.equal(peerA.seqRecv, 0n);
});

test('frame E2E serializa em ordem binária e valida tamanhos', () => {
  const sender = createPeer(keyA2B, keyB2A, ivA2B);
  const frame = encryptMessage(sender, Buffer.from('vetor'), idA, idB);
  const encoded = codificarFrameE2E(frame);
  const decoded = decodificarFrameE2E(encoded);

  assert.deepEqual(decoded.nonce, frame.nonce);
  assert.deepEqual(decoded.senderId, idA);
  assert.deepEqual(decoded.recipientId, idB);
  assert.equal(decoded.seqNo, 0n);
  assert.deepEqual(decoded.ciphertext, frame.ciphertext);
  assert.deepEqual(decoded.tag, frame.tag);
  assert.throws(() => decodificarFrameE2E(encoded.subarray(0, 20)), /truncado/);
});

test('rejeita nonce cujo contador não corresponde ao cabeçalho', () => {
  const sender = createPeer(keyA2B, keyB2A, ivA2B);
  const receiver = createPeer(keyB2A, keyA2B, ivB2A);
  const frame = encryptMessage(sender, Buffer.from('mensagem'), idA, idB);
  frame.nonce[11] ^= 1;

  assert.throws(() => decryptMessage(receiver, frame), /não corresponde/);
  assert.equal(receiver.ivBaseRecv, null);
  assert.equal(receiver.seqRecv, -1n);
});

test('rejeita mudança de IV_base depois que ele foi fixado', () => {
  const sender = createPeer(keyA2B, keyB2A, ivA2B);
  const receiver = createPeer(keyB2A, keyA2B, ivB2A);
  const first = encryptMessage(sender, Buffer.from('primeira'), idA, idB);
  decryptMessage(receiver, first);

  const second = encryptMessage(sender, Buffer.from('segunda'), idA, idB);
  second.nonce[0] ^= 1;
  assert.throws(() => decryptMessage(receiver, second), /ivBase.*mudou/);
  assert.deepEqual(receiver.ivBaseRecv, ivA2B);
  assert.equal(receiver.seqRecv, 0n);
});

test('tag inválida não fixa ivBaseRecv nem avança seqRecv', () => {
  const sender = createPeer(keyA2B, keyB2A, ivA2B);
  const receiver = createPeer(keyB2A, keyA2B, ivB2A);
  const frame = encryptMessage(sender, Buffer.from('adulterada'), idA, idB);
  frame.tag[0] ^= 1;

  assert.throws(() => decryptMessage(receiver, frame));
  assert.equal(receiver.ivBaseRecv, null);
  assert.equal(receiver.seqRecv, -1n);
});

test('rejeita replay sem alterar o estado do receptor', () => {
  const sender = createPeer(keyA2B, keyB2A, ivA2B);
  const receiver = createPeer(keyB2A, keyA2B, ivB2A);
  const frame = encryptMessage(sender, Buffer.from('uma vez'), idA, idB);
  decryptMessage(receiver, frame);

  assert.throws(() => decryptMessage(receiver, frame), /repetido/);
  assert.deepEqual(receiver.ivBaseRecv, ivA2B);
  assert.equal(receiver.seqRecv, 0n);
});
