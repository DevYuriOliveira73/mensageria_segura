import { createConnection, type Socket } from 'node:net';

export async function conectar(host: string, port: number): Promise<Socket> {
  const socket = createConnection({ host, port });
  await new Promise<void>((resolve, reject) => {
    const onConnect = (): void => {
      socket.off('error', onError);
      resolve();
    };
    const onError = (error: Error): void => {
      socket.off('connect', onConnect);
      reject(error);
    };
    socket.once('connect', onConnect);
    socket.once('error', onError);
  });
  return socket;
}

export async function* linhasDeEntrada(): AsyncGenerator<string> {
  let buffer = Buffer.alloc(0);
  for await (const chunk of process.stdin) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    buffer = Buffer.concat([buffer, bytes]);
    let newline = buffer.indexOf(0x0a);
    while (newline >= 0) {
      let line = buffer.subarray(0, newline);
      if (line.at(-1) === 0x0d) line = line.subarray(0, line.length - 1);
      yield line.toString('utf8');
      buffer = buffer.subarray(newline + 1);
      newline = buffer.indexOf(0x0a);
    }
  }
  if (buffer.length > 0) yield buffer.toString('utf8');
}

export function mensagemErro(error: unknown): string {
  return error instanceof Error ? error.message : 'erro desconhecido';
}
