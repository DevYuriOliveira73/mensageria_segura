const MAX_SEQ_NO = 0xffff_ffff_ffff_ffffn;

export function validarTamanho(buffer: Buffer, tamanho: number, nome: string): void {
  if (buffer.length !== tamanho) {
    throw new Error(`${nome} deve ter exatamente ${tamanho} bytes`);
  }
}

export function validarTamanhoMaximo(buffer: Buffer, limite: number, nome: string): void {
  if (buffer.length > limite) {
    throw new Error(`${nome} excede ${limite} bytes`);
  }
}

export function validarSeqNo(seqNo: bigint, nome = 'seq_no'): void {
  if (seqNo < 0n || seqNo > MAX_SEQ_NO) {
    throw new Error(`${nome} deve ser um inteiro unsigned de 64 bits`);
  }
}
