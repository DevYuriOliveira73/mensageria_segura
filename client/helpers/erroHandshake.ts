export class ErroHandshake extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ErroHandshake';
  }
}