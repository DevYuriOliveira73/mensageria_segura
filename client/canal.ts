import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from 'node:crypto';
import { isUtf8 } from 'node:buffer';
import type { Socket } from 'node:net';

import { codificarFrame, escreverTcp, LeitorTcp } from './framing.js';
import { montarNonce, validarNonce, type PeerState } from './e2e.js';

const TAMANHO_NONCE = 12;
const TAMANHO_SEQ = 8;
const TAMANHO_TAG = 16;
const TAMANHO_IV_BASE = 4;
const TAMANHO_MINIMO_FRAME = TAMANHO_NONCE + TAMANHO_SEQ + TAMANHO_TAG;
const CHAVE_SERVIDOR = Buffer.from('server', 'ascii');

export class CanalSeguro {
  private readonly estado: PeerState;
  private readonly clientIdBytes: Buffer;

  constructor(
    private readonly socket: Socket,
    private readonly leitor: LeitorTcp,
    clientIdBytes: Buffer,
    keySend: Buffer,
    keyRecv: Buffer,
  ) {
    if (clientIdBytes.length !== 16) {
      throw new Error('client_id do canal deve ter exatamente 16 bytes');
    }
    validarChave(keySend);
    validarChave(keyRecv);
    this.clientIdBytes = Buffer.from(clientIdBytes);
    this.estado = {
      keySend: Buffer.from(keySend),
      keyRecv: Buffer.from(keyRecv),
      seqSend: 0n,
      seqRecv: -1n,
      ivBaseSend: randomIvBase(),
      ivBaseRecv: null,
    };
  }

  async enviarJson(json: string): Promise<void> {
    const seqNo = this.estado.seqSend;
    const nonce = montarNonce(this.estado.ivBaseSend, seqNo);
    const cipher = createCipheriv('aes-128-gcm', this.estado.keySend, nonce, {
      authTagLength: TAMANHO_TAG,
    });
    cipher.setAAD(Buffer.concat([this.clientIdBytes, seqBytes(seqNo)]));

    const plaintext = Buffer.from(json, 'utf8');
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const body = Buffer.concat([nonce, seqBytes(seqNo), ciphertext, tag]);
    const framed = codificarFrame(body);
    this.estado.seqSend += 1n;
    try {
      await escreverTcp(this.socket, framed);
    } catch (error) {
      this.socket.destroy();
      throw error;
    }
  }

  async receberJson(): Promise<string | null> {
    const body = await this.leitor.lerFrame();
    if (body === null) return null;
    if (body.length < TAMANHO_MINIMO_FRAME) {
      throw new Error('Frame do canal menor que nonce, contador e tag');
    }

    const nonce = Buffer.from(body.subarray(0, TAMANHO_NONCE));
    const seqNo = body.readBigUInt64BE(TAMANHO_NONCE);
    const candidateIvBase = validarNonce(nonce, seqNo, this.estado);
    const inicioCiphertext = TAMANHO_NONCE + TAMANHO_SEQ;
    const inicioTag = body.length - TAMANHO_TAG;
    const ciphertext = body.subarray(inicioCiphertext, inicioTag);
    const tag = body.subarray(inicioTag);

    const decipher = createDecipheriv('aes-128-gcm', this.estado.keyRecv, nonce, {
      authTagLength: TAMANHO_TAG,
    });
    decipher.setAAD(Buffer.concat([CHAVE_SERVIDOR, seqBytes(seqNo)]));
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    if (this.estado.ivBaseRecv === null) {
      this.estado.ivBaseRecv = Buffer.from(candidateIvBase);
    }
    this.estado.seqRecv = seqNo;
    if (!isUtf8(plaintext)) {
      throw new Error('Plaintext do canal não é UTF-8 válido');
    }
    return plaintext.toString('utf8');
  }
}

function randomIvBase(): Buffer {
  return randomBytes(TAMANHO_IV_BASE);
}

function seqBytes(seqNo: bigint): Buffer {
  if (seqNo < 0n || seqNo > 0xffff_ffff_ffff_ffffn) {
    throw new Error('seq_no do canal deve ser unsigned de 64 bits');
  }
  const bytes = Buffer.alloc(TAMANHO_SEQ);
  bytes.writeBigUInt64BE(seqNo);
  return bytes;
}

function validarChave(key: Buffer): void {
  if (key.length !== 16) {
    throw new Error('Chave AES-128 do canal deve ter exatamente 16 bytes');
  }
}
