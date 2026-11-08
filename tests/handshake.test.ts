import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import test from 'node:test';

import {
  ErroHandshake,
  validarRespostaHandshake,
} from '../client/handshake.js';

const clientId = '00000000-0000-4000-8000-000000000001';
const clientPublicKey = Buffer.alloc(32, 2);
const serverPublicKey = Buffer.alloc(32, 3);
const salt = Buffer.alloc(16, 4);
const pinnedCertificate = readFileSync(
  new URL('../server/src/keys/certificado.crt', import.meta.url),
);

function response(
  certificate: Buffer,
  signature: Buffer,
): Record<string, string> {
  return {
    pk_S: serverPublicKey.toString('base64'),
    server_crt: certificate.toString('base64'),
    signature: signature.toString('base64'),
    salt_srv: salt.toString('base64'),
  };
}

test('handshake recusa certificado que não corresponde ao pin', () => {
  assert.throws(
    () => validarRespostaHandshake(
      response(Buffer.from('certificado diferente'), Buffer.alloc(256, 1)),
      clientId,
      clientPublicKey,
      pinnedCertificate,
    ),
    ErroHandshake,
  );
});

test('handshake rejeita assinatura RSA-PSS inválida mesmo com certificado pinado', () => {
  const certificate = new X509Certificate(pinnedCertificate);
  const signatureLength = (certificate.publicKey.asymmetricKeyDetails?.modulusLength ?? 2048) / 8;

  assert.throws(
    () => validarRespostaHandshake(
      response(pinnedCertificate, Buffer.alloc(signatureLength)),
      clientId,
      clientPublicKey,
      pinnedCertificate,
    ),
    /Assinatura RSA-PSS/,
  );
});
