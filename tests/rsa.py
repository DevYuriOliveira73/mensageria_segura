from Crypto.Hash import SHA256
from Crypto.Signature import pss
from Crypto.PublicKey import RSA

with open('server.key', 'rb') as f:
    skey_server = RSA.import_key(f.read())

with open('certificado.crt', 'rb') as f:
    pkey_server = RSA.import_key(f.read())

mensagem = b'Ola, essa mensagem e daora o'

digest = SHA256.new(mensagem) # Digest é o resultado final do algoritmo

signature = pss.new(skey_server).sign(digest) # Assinamos o hash, dessa forma a mensagem pode ter qualquer tamanho

print(f'Assinatura massa: {len(signature)} bytes')

fake = b'Mensagem adulterada aqui'

fake_digest = SHA256.new(fake)

try:
    check = pss.new(pkey_server).verify(fake_digest, signature)
    print('Assinatura valida')
except ValueError:
    print(f'Assinatura invalida!')