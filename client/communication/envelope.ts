import { uuidParaBytes } from '../cryptography/keys.js';
import type {
  ControleEnvelope,
  EnvelopeServidor,
  MensagemEnvelope,
} from './types.js';

export class ErroEnvelope extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ErroEnvelope';
  }
}

export function criarEnvelopeMensagem(
  senderId: string,
  recipientId: string,
  seqNo: bigint,
  nonce: Buffer,
  ciphertext: Buffer,
): MensagemEnvelope {
  validarUuid(senderId, 'sender_id');
  validarUuid(recipientId, 'recipient_id');
  if (seqNo < 0n || seqNo > 0xffff_ffff_ffff_ffffn) {
    throw new ErroEnvelope('seq_no deve ser unsigned de 64 bits');
  }
  if (nonce.length !== 12 || ciphertext.length === 0) {
    throw new ErroEnvelope('Nonce ou ciphertext inválido');
  }
  return { kind: 'message', senderId, recipientId, seqNo, nonce: Buffer.from(nonce), ciphertext };
}

export function serializarEnvelope(envelope: MensagemEnvelope): string {
  return JSON.stringify({
    sender_id: envelope.senderId,
    recipient_id: envelope.recipientId,
    seq_no: envelope.seqNo.toString(),
    nonce: envelope.nonce.toString('base64'),
    ciphertext: envelope.ciphertext.toString('base64'),
  });
}

export function analisarEnvelope(json: string): EnvelopeServidor {
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch (error) {
    throw new ErroEnvelope(`JSON de envelope inválido: ${mensagemErro(error)}`);
  }
  if (!isRecord(value)) {
    throw new ErroEnvelope('Envelope deve ser um objeto JSON');
  }

  const senderId = stringField(value, 'sender_id');
  const recipientId = stringField(value, 'recipient_id');
  validarUuid(recipientId, 'recipient_id');
  const nonce = decodificarBase64(stringField(value, 'nonce'), 'nonce');
  if (nonce.length !== 12) {
    throw new ErroEnvelope('nonce deve ter exatamente 12 bytes');
  }

  if (value.control === true) {
    if (senderId !== 'server') {
      throw new ErroEnvelope('Mensagem de controle deve ter sender_id "server"');
    }
    return analisarControle(value, recipientId, nonce);
  }

  if (value.control !== undefined && value.control !== false) {
    throw new ErroEnvelope('Campo control deve ser booleano');
  }

  validarUuid(senderId, 'sender_id');
  const seqNo = analisarSeqNo(value.seq_no);
  const ciphertext = decodificarBase64(stringField(value, 'ciphertext'), 'ciphertext');
  return { kind: 'message', senderId, recipientId, seqNo, nonce, ciphertext };
}

export function uuidEmBytes(clientId: string): Buffer {
  try {
    return uuidParaBytes(clientId);
  } catch (error) {
    throw new ErroEnvelope(mensagemErro(error));
  }
}

function analisarControle(
  value: Record<string, unknown>,
  recipientId: string,
  nonce: Buffer,
): ControleEnvelope {
  const seqNo = value.seq_no;
  if (typeof seqNo !== 'number' || !Number.isSafeInteger(seqNo) || seqNo < 0) {
    throw new ErroEnvelope('seq_no de controle deve ser um inteiro seguro não negativo');
  }
  if (!isRecord(value.ciphertext)) {
    throw new ErroEnvelope('ciphertext de controle deve ser um objeto');
  }
  const info = value.ciphertext.info;
  const rawData = value.ciphertext.data;
  if (info !== 'new_user' && info !== 'user_exit') {
    throw new ErroEnvelope('Tipo de controle desconhecido');
  }
  if (!Array.isArray(rawData) || !rawData.every((item) => typeof item === 'string')) {
    throw new ErroEnvelope('data de controle deve ser uma lista de strings');
  }
  const expectedLength = info === 'new_user' ? 2 : 1;
  if (rawData.length !== expectedLength) {
    throw new ErroEnvelope(`Quantidade de campos inválida para ${info}`);
  }
  if (info === 'new_user') {
    validarUuid(rawData[0], 'client_id de new_user');
    decodificarChavePublica(rawData[1]);
  } else {
    validarUuid(rawData[0], 'client_id de user_exit');
  }

  return {
    kind: 'control',
    senderId: 'server',
    recipientId,
    seqNo,
    nonce,
    info,
    data: [...rawData],
  };
}

export function decodificarChavePublica(encoded: string): Buffer {
  const key = decodificarBase64(encoded, 'chave pública');
  if (key.length !== 32) {
    throw new ErroEnvelope('Chave pública X25519 deve ter exatamente 32 bytes');
  }
  return key;
}

function analisarSeqNo(value: unknown): bigint {
  if (
    (typeof value !== 'string' && typeof value !== 'number') ||
    (typeof value === 'number' && (!Number.isSafeInteger(value) || value < 0)) ||
    (typeof value === 'string' && !/^\d+$/.test(value))
  ) {
    throw new ErroEnvelope('seq_no inválido');
  }
  const seqNo = BigInt(value);
  if (seqNo > 0xffff_ffff_ffff_ffffn) {
    throw new ErroEnvelope('seq_no excede 64 bits');
  }
  return seqNo;
}

function decodificarBase64(value: string, field: string): Buffer {
  if (value.length === 0 || value.length % 4 !== 0 || !/^(?:[\da-z+/]{4})*(?:[\da-z+/]{2}==|[\da-z+/]{3}=)?$/i.test(value)) {
    throw new ErroEnvelope(`${field} não está em Base64 válido`);
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64') !== value) {
    throw new ErroEnvelope(`${field} não está em Base64 canônico`);
  }
  return decoded;
}

function validarUuid(value: string, field: string): void {
  try {
    uuidParaBytes(value);
  } catch {
    throw new ErroEnvelope(`${field} deve ser um UUID válido`);
  }
}

function stringField(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== 'string') {
    throw new ErroEnvelope(`${key} deve ser uma string`);
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function mensagemErro(error: unknown): string {
  return error instanceof Error ? error.message : 'erro desconhecido';
}
