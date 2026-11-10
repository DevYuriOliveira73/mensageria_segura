import type { PeerState } from '../cryptography/e2e.js';

export interface Peer {
  publicKey: Buffer;
  state: PeerState;
}
