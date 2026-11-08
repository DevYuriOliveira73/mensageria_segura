import assert from 'node:assert/strict';
import test from 'node:test';

import {
  analisarEnvelope,
  criarEnvelopeMensagem,
  serializarEnvelope,
} from '../client/envelope.js';

const idA = '00000000-0000-4000-8000-000000000001';
const idB = '00000000-0000-4000-8000-000000000002';
const nonce = Buffer.from('0102030405060708090a0b0c', 'hex');

test('round-trip preserva seq_no acima da precisão numérica JSON', () => {
  const seqNo = 9_007_199_254_740_993n;
  const original = criarEnvelopeMensagem(idA, idB, seqNo, nonce, Buffer.from([1, 2, 3]));
  const decoded = analisarEnvelope(serializarEnvelope(original));

  assert.equal(decoded.kind, 'message');
  if (decoded.kind !== 'message') return;
  assert.equal(decoded.seqNo, seqNo);
  assert.deepEqual(decoded.nonce, nonce);
  assert.deepEqual(decoded.ciphertext, Buffer.from([1, 2, 3]));
});

test('aceita controle new_user com ID e chave X25519 raw em Base64', () => {
  const control = {
    sender_id: 'server',
    recipient_id: idA,
    seq_no: 0,
    nonce: nonce.toString('base64'),
    control: true,
    ciphertext: {
      info: 'new_user',
      data: [idB, Buffer.alloc(32, 7).toString('base64')],
    },
  };
  const envelope = analisarEnvelope(JSON.stringify(control));

  assert.equal(envelope.kind, 'control');
  if (envelope.kind !== 'control') return;
  assert.equal(envelope.info, 'new_user');
  assert.equal(envelope.data[0], idB);
});

test('rejeita Base64, nonce, destino e estrutura de controle inválidos', () => {
  const valid = {
    sender_id: idA,
    recipient_id: idB,
    seq_no: '0',
    nonce: nonce.toString('base64'),
    ciphertext: Buffer.from([1]).toString('base64'),
  };

  assert.throws(
    () => analisarEnvelope(JSON.stringify({ ...valid, nonce: '***' })),
    /Base64/,
  );
  assert.throws(
    () => analisarEnvelope(JSON.stringify({ ...valid, recipient_id: 'server' })),
    /UUID/,
  );
  assert.throws(
    () => analisarEnvelope(JSON.stringify({
      ...valid,
      seq_no: 0,
      control: true,
      sender_id: 'server',
      ciphertext: { info: 'new_user', data: [idB, 'AQ=='] },
    })),
    /32 bytes/,
  );
});
