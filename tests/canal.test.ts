import assert from 'node:assert/strict';
import {
  createCipheriv,
  createDecipheriv,
} from 'node:crypto';
import test from 'node:test';
import {
  createConnection,
  createServer,
  type Socket,
} from 'node:net';

import { CanalSeguro } from '../client/canal.js';
import { codificarFrame, escreverTcp, LeitorTcp } from '../client/framing.js';
import { uuidParaBytes } from '../client/keys.js';

const clientId = '00000000-0000-4000-8000-000000000001';
const clientIdBytes = uuidParaBytes(clientId);
const keyC2S = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
const keyS2C = Buffer.from('101112131415161718191a1b1c1d1e1f', 'hex');
const ivBaseServer = Buffer.from('a1a2a3a4', 'hex');

test('canal mantém seq_no C2S e S2C independentes e autentica ambos os sentidos', async (t) => {
  const server = createServer();
  const accepted = new Promise<Socket>((resolve) => {
    server.once('connection', resolve);
  });
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address !== 'string');

  const clientSocket = createConnection({ host: '127.0.0.1', port: address.port });
  const serverSocket = await accepted;
  await new Promise<void>((resolve, reject) => {
    clientSocket.once('connect', resolve);
    clientSocket.once('error', reject);
  });
  t.after(async () => {
    clientSocket.destroy();
    serverSocket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  const clientReader = new LeitorTcp(clientSocket);
  const serverReader = new LeitorTcp(serverSocket);
  const canal = new CanalSeguro(clientSocket, clientReader, clientIdBytes, keyC2S, keyS2C);

  for (let seqNo = 0n; seqNo < 2n; seqNo += 1n) {
    await canal.enviarJson(JSON.stringify({ seq_no: (seqNo + 9n).toString() }));
    const body = await serverReader.lerFrame();
    assert.ok(body);
    assert.equal(body.readBigUInt64BE(12), seqNo);
    assert.equal(body.subarray(4, 12).readBigUInt64BE(0), seqNo);

    const decipher = createDecipheriv('aes-128-gcm', keyC2S, body.subarray(0, 12), {
      authTagLength: 16,
    });
    const seqBytes = Buffer.alloc(8);
    seqBytes.writeBigUInt64BE(seqNo);
    decipher.setAAD(Buffer.concat([clientIdBytes, seqBytes]));
    decipher.setAuthTag(body.subarray(-16));
    const clientPlaintext = Buffer.concat([
      decipher.update(body.subarray(20, -16)),
      decipher.final(),
    ]);
    assert.equal(JSON.parse(clientPlaintext.toString('utf8')).seq_no, (seqNo + 9n).toString());

    const serverNonce = Buffer.alloc(12);
    ivBaseServer.copy(serverNonce);
    serverNonce.writeBigUInt64BE(seqNo, 4);
    const cipher = createCipheriv('aes-128-gcm', keyS2C, serverNonce, {
      authTagLength: 16,
    });
    cipher.setAAD(Buffer.concat([Buffer.from('server', 'ascii'), seqBytes]));
    const serverPlaintext = Buffer.from(JSON.stringify({ reply: seqNo.toString() }), 'utf8');
    const ciphertext = Buffer.concat([cipher.update(serverPlaintext), cipher.final()]);
    await escreverTcp(
      serverSocket,
      codificarFrame(Buffer.concat([serverNonce, seqBytes, ciphertext, cipher.getAuthTag()])),
    );
    assert.equal(
      await canal.receberJson(),
      JSON.stringify({ reply: seqNo.toString() }),
    );
  }
});
