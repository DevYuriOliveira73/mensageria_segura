import { readFileSync } from 'node:fs';

import { CanalSeguro } from './communication/canal.js';
import { uuidEmBytes } from './communication/envelope.js';
import { LeitorTcp } from './communication/framing.js';
import { executarHandshake } from './communication/handshake.js';
import {
  conectar,
  linhasDeEntrada,
  mensagemErro
} from './application/runtime.js';
import {
  receberMensagens,
  processarComando,
  type Peer,
} from './application/mensagens.js';

const HOST_PADRAO = '127.0.0.1';
const PORTA_PADRAO = 9000;
const CERTIFICADO_PINADO = new URL(
  '../server/src/keys/certificado.crt',
  import.meta.url,
);

async function main(): Promise<void> {
  const host = HOST_PADRAO;
  const port = PORTA_PADRAO;
  const socket = await conectar(host, port);

  try {
    const leitor = new LeitorTcp(socket);
    const certificado = readFileSync(CERTIFICADO_PINADO);

    // Executa o handshake e estabelece o canal seguro
    const sessao = await executarHandshake(socket, leitor, certificado);
    const canal = new CanalSeguro(
      socket,
      leitor,
      uuidEmBytes(sessao.clientId),
      sessao.channelKeys.c2s,
      sessao.channelKeys.s2c,
    );
    const peers = new Map<string, Peer>();

    console.log(`Conectado como ${sessao.clientId}`);
    console.log('Comandos: /peers, /msg <client_id> <mensagem>, /quit');
    let encerrando = false;
    const recebimento = receberMensagens(
      canal,
      sessao.clientId,
      sessao.keyPair.privateKey,
      sessao.keyPair.publicKey,
      peers,
      () => encerrando,
    );

    try {
      process.stdout.write('> ');
      for await (const line of linhasDeEntrada()) {
        const command = line.trim();
        if (command.length === 0) {
          process.stdout.write('> ');
          continue;
        }
        if (command === '/quit') break;
        try {
          await processarComando(command, canal, sessao.clientId, peers);
        } catch (error) {
          console.error(`Comando rejeitado: ${mensagemErro(error)}`);
          if (socket.destroyed) throw error;
        }
        process.stdout.write('> ');
      }
    } finally {
      encerrando = true;
      socket.end();
    }

    await recebimento;
  } finally {
    if (!socket.destroyed) socket.destroy();
  }
}

void main().catch((error: unknown) => {
  console.error(`Falha no cliente: ${mensagemErro(error)}`);
  process.exitCode = 1;
});
