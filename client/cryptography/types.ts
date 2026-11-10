import type { KeyObject } from 'node:crypto';

export type DirecaoE2E = 'A2B' | 'B2A';

export interface ParX25519 {
  privateKey: KeyObject;
  publicKey: Buffer;
}

export interface ChavesPar {
  keySend: Buffer;
  keyRecv: Buffer;
  sendLabel: DirecaoE2E;
  receiveLabel: DirecaoE2E;
}

export interface ChavesCanal {
  c2s: Buffer;
  s2c: Buffer;
}
