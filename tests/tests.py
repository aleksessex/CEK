from sys import path

path.append('..')
path.append('src')

from cek import Cryptosystem

# Initialize keypairs for testing
keypairs = []
# Keypair data values
samples = ["CEK OP"]
# Encrypted data values
encrypted_data = []

def gen_keypairs():
    for index in range(1):
        keypairs.append(Cryptosystem())
        print("Keypair Object #{} created successfully").format(index + 1)
        assert index == len(keypairs) - 1

def gen_keys():
    for index, keypair in enumerate(keypairs):
        gen_key(index + 1, keypair)

def gen_key(index, keypair):
    keypair.generate_key()
    print("Keypair #{} pub/priv key generated").format(index)
    assert type(keypair) is Cryptosystem

def encrypt_keys():
    for index, keypair in enumerate(keypairs):
        encrypt_key(index + 1, keypair)

def encrypt_key(index, keypair):
    enc_data = keypair.encrypt(samples[0])
    encrypted_data.append(enc_data)
    print("Keypair #{} encrypted data: {}").format(index, samples[0])
    assert type(long(enc_data)) is long

def decrypt_keys():
    for index, keypair in enumerate(keypairs):
        decrypt_key(index + 1, keypair, encrypted_data[index])

def decrypt_key(index, keypair, enc_data):
    value = keypair.decrypt(enc_data) # Problem with decrypt - always return `Inf`
    print("Keypair #{} data decrypted: {}").format(index, value)


# Start testing suite
gen_keypairs()
gen_keys()
encrypt_keys()
decrypt_keys()
