export interface MensagemEnvelope {
  kind: 'message';
  senderId: string;
  recipientId: string;
  seqNo: bigint;
  nonce: Buffer;
  ciphertext: Buffer;
}

export interface ControleEnvelope {
  kind: 'control';
  senderId: 'server';
  recipientId: string;
  seqNo: number;
  nonce: Buffer;
  info: 'new_user' | 'user_exit';
  data: string[];
}

export type EnvelopeServidor = MensagemEnvelope | ControleEnvelope;
