from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

skey_bob = X25519PrivateKey.generate()
skey_alice = X25519PrivateKey.generate()

pkey_bob = skey_bob.public_key()
pkey_alice = skey_alice.public_key()

pkey_alice_bytes = pkey_alice.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

print(pkey_alice_bytes)

alice_secret = skey_alice.exchange(pkey_bob)
bob_secret = skey_bob.exchange(pkey_alice)

assert alice_secret == bob_secret

print(alice_secret)

print(f'Tudo certo mulekote')


