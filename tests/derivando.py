from cryptography.hazmat.primitives.kdf.hkdf import HKDF # Função de derivação de chaves
from cryptography.hazmat.primitives.hashes import SHA256

alice_secret = b'Segredo que foi compartilhado'
salt = b'saltaleatorioai'

# Os dois clientes devem derivar essas 2 chaves igualmente

k_a2b = HKDF( # Pega um segredo e gera uma chave ou multiplas (Nesse codigo geramos 2) 
    algorithm=SHA256(), # Usada aqui para mistura e expansão no algorítmo
    length=16, # Tamanho da chave 
    salt=salt, # O salt aleatorio
    info=b'a2b' # Uma info para gerar uma chave diferente
).derive(alice_secret) # Deriva a chave o retorna os bytes dela

k_b2a = HKDF(
    algorithm=SHA256(),
    length=16,
    salt=salt,
    info=b'b2a'
).derive(alice_secret)

# A partir daqui ja podemos usar no AES-128

print(k_a2b)
print(k_b2a)