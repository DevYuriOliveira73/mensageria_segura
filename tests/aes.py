from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(16) # A chave teria sido obtida com o HKDF
nonce = get_random_bytes(12) # Um nonce unico por pacote e direção, aleatorio mesmo
# O nonce é semelhante ao iv, mas diferente do iv que foi feito pra uso em blocos no aes cbc, 
# o nonce seria uma especie de valor numerico unico

plaintext = b'mensagem daora mano'
aad = b'sender_id|recipient_id|seq_no'

cipher = AES.new(
    key=key,
    mode=AES.MODE_GCM,
    nonce=nonce
)

# GCM, o que é? É um modo do aes que une o aes com autenticação
# Gera o texto e uma tag que verifica se o dado foi adulterado

cipher.update(aad) # Dado associado que não vai ser criptografado, mas o gcm ainda vai ver alteração

cipher_text, tag = cipher.encrypt_and_digest(plaintext=plaintext)
# Retorna texto cifrado em bytes e tag MAC

print(cipher_text.hex())
print(tag.hex())


# Descriptografando:

cipher_d = AES.new(
    key=key,
    mode=AES.MODE_GCM,
    nonce=nonce
)

cipher_d.update(aad)

try:
    dec_data = cipher_d.decrypt_and_verify(ciphertext=cipher_text, received_mac_tag=tag)
    print(dec_data)
except ValueError:
    print(f'Mensagem invalida')
