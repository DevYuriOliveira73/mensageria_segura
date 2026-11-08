import type { Socket } from 'node:net';

const TAMANHO_PREFIXO = 4;
export const LIMITE_FRAME = 8 * 1024;
const TAMANHO_MAXIMO_PREFIXO = 0xffff_ffff;

export class ErroFrame extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ErroFrame';
  }
}

export class LeitorTcp {
  private readonly chunks: AsyncIterator<Buffer>;
  private buffer = Buffer.alloc(0);
  private encerrado = false;

  constructor(socket: Socket) {
    this.chunks = socket[Symbol.asyncIterator]();
  }

  async lerExatamente(tamanho: number): Promise<Buffer | null> {
    if (!Number.isSafeInteger(tamanho) || tamanho < 0 || tamanho > TAMANHO_MAXIMO_PREFIXO) {
      throw new ErroFrame('Tamanho de leitura inválido');
    }

    while (this.buffer.length < tamanho && !this.encerrado) {
      const resultado = await this.chunks.next();
      if (resultado.done) {
        this.encerrado = true;
        break;
      }
      this.buffer = Buffer.concat([this.buffer, resultado.value]);
    }

    if (this.buffer.length < tamanho) {
      if (this.buffer.length === 0) return null;
      throw new ErroFrame('Conexão encerrada durante a leitura de um frame');
    }

    const bytes = Buffer.from(this.buffer.subarray(0, tamanho));
    this.buffer = this.buffer.subarray(tamanho);
    return bytes;
  }

  async lerFrame(): Promise<Buffer | null> {
    const prefixo = await this.lerExatamente(TAMANHO_PREFIXO);
    if (prefixo === null) return null;

    const tamanho = prefixo.readUInt32BE(0);
    validarTamanho(tamanho);
    const payload = await this.lerExatamente(tamanho);
    if (payload === null) {
      throw new ErroFrame('Conexão encerrada antes do corpo do frame');
    }
    return payload;
  }
}

export function escreverTcp(socket: Socket, bytes: Buffer): Promise<void> {
  return new Promise((resolve, reject) => {
    const onError = (error: Error): void => {
      socket.off('error', onError);
      reject(error);
    };

    socket.once('error', onError);
    socket.write(bytes, (error?: Error | null) => {
      socket.off('error', onError);
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

export function codificarFrame(payload: Buffer): Buffer {
  validarTamanho(payload.length);

  const frame = Buffer.alloc(TAMANHO_PREFIXO + payload.length);
  frame.writeUInt32BE(payload.length, 0);
  payload.copy(frame, TAMANHO_PREFIXO);
  return frame;
}

export class DecodificadorFrames {
  private buffer = Buffer.alloc(0);

  adicionar(chunk: Buffer): Buffer[] {
    if (chunk.length === 0) return [];

    this.buffer = Buffer.concat([this.buffer, chunk]);
    const frames: Buffer[] = [];
    let offset = 0;

    while (this.buffer.length - offset >= TAMANHO_PREFIXO) {
      const tamanho = this.buffer.readUInt32BE(offset);
      validarTamanho(tamanho);

      const inicioPayload = offset + TAMANHO_PREFIXO;
      const fimPayload = inicioPayload + tamanho;
      if (this.buffer.length < fimPayload) break;

      frames.push(Buffer.from(this.buffer.subarray(inicioPayload, fimPayload)));
      offset = fimPayload;
    }

    if (offset > 0) {
      this.buffer = Buffer.from(this.buffer.subarray(offset));
    }

    return frames;
  }
}

function validarTamanho(tamanho: number): void {
  if (tamanho === 0) {
    throw new ErroFrame('Frame vazio não é válido');
  }
  if (tamanho > LIMITE_FRAME) {
    throw new ErroFrame(`Frame excede o limite de ${LIMITE_FRAME} bytes`);
  }
}
