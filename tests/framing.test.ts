import assert from 'node:assert/strict';
import test from 'node:test';

import {
  codificarFrame,
  DecodificadorFrames,
  ErroFrame,
  LIMITE_FRAME,
} from '../client/framing.js';

test('codifica comprimento de 4 bytes big-endian e decodifica o payload', () => {
  const payload = Buffer.from('frame');
  const frame = codificarFrame(payload);

  assert.equal(frame.readUInt32BE(0), payload.length);
  assert.deepEqual(new DecodificadorFrames().adicionar(frame), [payload]);
});

test('mantém prefixo e corpo parciais até receber o frame completo', () => {
  const payload = Buffer.from('mensagem');
  const frame = codificarFrame(payload);
  const decoder = new DecodificadorFrames();

  assert.deepEqual(decoder.adicionar(frame.subarray(0, 2)), []);
  assert.deepEqual(decoder.adicionar(frame.subarray(2, 7)), []);
  assert.deepEqual(decoder.adicionar(frame.subarray(7)), [payload]);
});

test('decodifica múltiplos frames recebidos no mesmo chunk', () => {
  const first = Buffer.from('primeiro');
  const second = Buffer.from('segundo');
  const decoder = new DecodificadorFrames();

  assert.deepEqual(
    decoder.adicionar(Buffer.concat([codificarFrame(first), codificarFrame(second)])),
    [first, second],
  );
});

test('rejeita frames vazios ou acima do limite', () => {
  const decoder = new DecodificadorFrames();
  const emptyFrame = Buffer.alloc(4);
  const oversizedFrame = Buffer.alloc(4);
  oversizedFrame.writeUInt32BE(LIMITE_FRAME + 1);

  assert.throws(() => decoder.adicionar(emptyFrame), ErroFrame);
  assert.throws(() => decoder.adicionar(oversizedFrame), ErroFrame);
  assert.throws(() => codificarFrame(Buffer.alloc(LIMITE_FRAME + 1)), ErroFrame);
});
