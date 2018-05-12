from sys import path

path.append('..')
path.append('src')

from cek import Cryptosystem

# Initialize keypairs for testing
keypairs = []
# Keypair data values
samples = ["CEK OP"]
samples_keys = [1111]
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

def add_keys_data():
    for index, keypair in enumerate(keypairs):
        add_key_data(index + 1, keypair)

def add_key_data(index, keypair):
    sample_key = keypair.rerandomize(samples_keys[0])
    samples_keys[0] = sample_key
    print("Keypair #{} key created {}").format(index, type(long(sample_key)))
    assert type(long(sample_key)) is long

    enc_data = keypair.encrypt(samples[0])
    encrypted_data.append(enc_data)
    print("Keypair #{} encrypted data {}").format(index, type(long(enc_data)))
    assert type(long(enc_data)) is long

def decrypt_keys():
    for index, keypair in enumerate(keypairs):
        decrypt_key(index + 1, keypair)

def decrypt_key(index, keypair):
    print("Decryption suite needs to be discussed...")
    '''
    value = keypair.decrypt(samples_keys[0])
    print("Keypair #{} data decrypted: {}").format(index, value)
    '''


# Start testing suite
gen_keypairs()
gen_keys()
add_keys_data()
decrypt_keys()
