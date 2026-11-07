# Como gerar uma chave privada rsa e um certificado x508 com o OpenSSL?

Simplesmente digite:

```sh
openssl req -x509 -newkey rsa:3072 -sha256 -days 365 -keyout server.key -out server.crt -subj "/CN=Mensageria TP3"
```

Isso vai gerar um certificado **server.crt** no formato x508 e uma chave privada **server.key**