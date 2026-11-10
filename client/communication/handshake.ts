import {
  constants,
  randomUUID,
  timingSafeEqual,
  verify,
  X509Certificate,
  type KeyObject,
} from 'node:crypto';
import type { Socket } from 'node:net';
import { ErroHandshake } from '../helpers/erroHandshake.js';

import { derivarChavesCanal, gerarParX25519, segredoCompartilhado, type ParX25519 } from '../cryptography/keys.js';
import { escreverTcp, LeitorTcp } from './framing.js';

const TAMANHO_PUBLICA_X25519 = 32;
const TAMANHO_SALT = 16;
const LIMITE_JSON_HANDSHAKE = 16 * 1024;

export interface SessaoHandshake {
  clientId: string;
  keyPair: ParX25519;
  channelKeys: {
    c2s: Buffer;
    s2c: Buffer;
  };
}

//Envia a primeira mensagem (to serv)
export async function executarHandshake(
  socket: Socket,
  leitor: LeitorTcp,
  certificadoPinado: Buffer,
): Promise<SessaoHandshake> {
  const clientId = randomUUID();
  const keyPair = gerarParX25519();
  const registro = JSON.stringify({
    client_id: clientId,
    pkey: keyPair.publicKey.toString('base64'),
  });

  await escreverTcp(socket, Buffer.from(registro, 'utf8'));
  const resposta = await lerObjetoJson(leitor);
  const { serverPublicKey, salt } = validarRespostaHandshake(
    resposta,
    clientId,
    keyPair.publicKey,
    certificadoPinado,
  );
  const sharedSecret = segredoCompartilhado(keyPair.privateKey, serverPublicKey);

  return {
    clientId,
    keyPair,
    channelKeys: derivarChavesCanal(sharedSecret, salt),
  };
}

export function validarRespostaHandshake(
  value: unknown,
  clientId: string,
  clientPublicKey: Buffer,
  certificadoPinado: Buffer,
): { serverPublicKey: Buffer; salt: Buffer } {
  if (!isRecord(value)) {
    throw new ErroHandshake('Resposta do servidor deve ser um objeto JSON');
  }

  const serverPublicKey = decodificarBase64(value.pk_S, 'pk_S');
  const certificateBytes = decodificarBase64(value.server_crt, 'server_crt');
  const signature = decodificarBase64(value.signature, 'signature');
  const salt = decodificarBase64(value.salt_srv, 'salt_srv');

  if (serverPublicKey.length !== TAMANHO_PUBLICA_X25519) {
    throw new ErroHandshake('pk_S deve ter exatamente 32 bytes');
  }
  if (salt.length !== TAMANHO_SALT) {
    throw new ErroHandshake('salt_srv deve ter exatamente 16 bytes');
  }
  if (certificateBytes.length !== certificadoPinado.length ||
      !timingSafeEqual(certificateBytes, certificadoPinado)) {
    throw new ErroHandshake('Certificado recebido não corresponde ao certificado pinado');
  }

  let certificate: X509Certificate;
  try {
    certificate = new X509Certificate(certificateBytes);
  } catch (error) {
    throw new ErroHandshake(`Certificado do servidor inválido: ${mensagemErro(error)}`);
  }
  const publicKey: KeyObject = certificate.publicKey;
  if (publicKey.asymmetricKeyType !== 'rsa') {
    throw new ErroHandshake('O certificado pinado não contém uma chave RSA');
  }
  const modulusLength = publicKey.asymmetricKeyDetails?.modulusLength;
  if (modulusLength !== undefined && modulusLength < 2048) {
    throw new ErroHandshake('A chave RSA do servidor deve ter pelo menos 2048 bits');
  }

  const signedMaterial = Buffer.concat([
    serverPublicKey,
    clientPublicKey,
    Buffer.from(clientId, 'utf8'),
    salt,
  ]);
  const signatureIsValid = verify(
    'sha256',
    signedMaterial,
    {
      key: publicKey,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
    },
    signature,
  );
  if (!signatureIsValid) {
    throw new ErroHandshake('Assinatura RSA-PSS do handshake inválida');
  }

  return { serverPublicKey, salt };
}

async function lerObjetoJson(leitor: LeitorTcp): Promise<unknown> {
  const bytes: Buffer[] = [];
  const delimitadores: number[] = [];
  let bytesLidos = 0;
  let iniciou = false;
  let dentroString = false;
  let escape = false;

  while (bytesLidos < LIMITE_JSON_HANDSHAKE) {
    const byteBuffer = await leitor.lerExatamente(1);
    if (byteBuffer === null) {
      throw new ErroHandshake('Servidor encerrou a conexão durante o handshake');
    }
    const byte = byteBuffer[0];
    bytesLidos += 1;

    if (!iniciou) {
      if (byte === 0x20 || byte === 0x0a || byte === 0x0d || byte === 0x09) continue;
      if (byte !== 0x7b) {
        throw new ErroHandshake('Resposta do handshake não começa com um objeto JSON');
      }
      iniciou = true;
      delimitadores.push(byte);
      bytes.push(byteBuffer);
      continue;
    }

    bytes.push(byteBuffer);
    if (dentroString) {
      if (escape) {
        escape = false;
      } else if (byte === 0x5c) {
        escape = true;
      } else if (byte === 0x22) {
        dentroString = false;
      }
      continue;
    }

    if (byte === 0x22) {
      dentroString = true;
    } else if (byte === 0x7b || byte === 0x5b) {
      delimitadores.push(byte);
    } else if (byte === 0x7d || byte === 0x5d) {
      const abertura = delimitadores.pop();
      if ((byte === 0x7d && abertura !== 0x7b) || (byte === 0x5d && abertura !== 0x5b)) {
        throw new ErroHandshake('Delimitadores inválidos na resposta JSON do handshake');
      }
      if (delimitadores.length === 0) {
        try {
          return JSON.parse(Buffer.concat(bytes).toString('utf8')) as unknown;
        } catch (error) {
          throw new ErroHandshake(`JSON de handshake inválido: ${mensagemErro(error)}`);
        }
      }
    }
  }

  throw new ErroHandshake('Resposta JSON do handshake excede o limite permitido');
}

function decodificarBase64(value: unknown, field: string): Buffer {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length % 4 !== 0 ||
    !/^(?:[\da-z+/]{4})*(?:[\da-z+/]{2}==|[\da-z+/]{3}=)?$/i.test(value)
  ) {
    throw new ErroHandshake(`${field} não está em Base64 válido`);
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64') !== value) {
    throw new ErroHandshake(`${field} não está em Base64 canônico`);
  }
  return decoded;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function mensagemErro(error: unknown): string {
  return error instanceof Error ? error.message : 'erro desconhecido';
}
