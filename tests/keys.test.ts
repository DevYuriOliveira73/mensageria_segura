import assert from 'node:assert/strict';
import test from 'node:test';

import {
  derivarChavesPar,
  gerarParX25519,
  saltDoPar,
  segredoCompartilhado,
  toRaw,
  fromRaw,
  uuidParaBytes,
} from '../client/keys.js';

const idA = Buffer.from('00000000000040008000000000000001', 'hex');
const idB = Buffer.from('00000000000040008000000000000002', 'hex');
const publicKeyA = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
const publicKeyB = Buffer.from('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f', 'hex');

test('saltDoPar é determinístico e independente da ordem dos participantes', () => {
  const saltAB = saltDoPar(idA, publicKeyA, idB, publicKeyB);
  const saltBA = saltDoPar(idB, publicKeyB, idA, publicKeyA);

  assert.equal(saltAB.length, 16);
  assert.deepEqual(saltAB, saltBA);
  assert.equal(saltAB.toString('hex'), '9dcbb0c1318b9958a9d908f442fc153e');
});

test('deriva chaves direcionais iguais e invertidas nos dois peers', () => {
  const sharedSecret = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
  const peerA = derivarChavesPar(idA, publicKeyA, idB, publicKeyB, sharedSecret);
  const peerB = derivarChavesPar(idB, publicKeyB, idA, publicKeyA, sharedSecret);

  assert.equal(peerA.sendLabel, 'A2B');
  assert.equal(peerB.sendLabel, 'B2A');
  assert.deepEqual(peerA.keySend, peerB.keyRecv);
  assert.deepEqual(peerA.keyRecv, peerB.keySend);
  assert.equal(peerA.keySend.toString('hex'), 'c40ae415b8bac48a65c7913ca3544170');
  assert.equal(peerA.keyRecv.toString('hex'), 'bbc3317e07708995fd4d06303fd159aa');
});

test('chaves públicas X25519 convertem para e de 32 bytes raw', () => {
  const local = gerarParX25519();
  const peer = gerarParX25519();
  const importedPublicKey = fromRaw(peer.publicKey);
  assert.deepEqual(toRaw(importedPublicKey), peer.publicKey);

  const secretLocal = segredoCompartilhado(local.privateKey, peer.publicKey);
  const secretPeer = segredoCompartilhado(peer.privateKey, local.publicKey);
  assert.deepEqual(secretLocal, secretPeer);
});

test('UUID textual é convertido para 16 bytes na ordem de rede', () => {
  assert.deepEqual(
    uuidParaBytes('00000000-0000-4000-8000-000000000001'),
    idA,
  );
  assert.throws(() => uuidParaBytes('nao-e-uuid'), /UUID/);
});
