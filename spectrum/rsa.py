from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def generate_keypair(keysize):
    return RSA.generate(keysize)


def write_private_key(keypair, private_keyfile):
    private_key = keypair.exportKey()  
    private_out = open(private_keyfile, "wb")
    private_out.write(private_key)
    private_out.close()
    return


def read_private_key(private_keyfile):
    return RSA.importKey(open(private_keyfile).read())


def write_public_key(keypair, public_keyfile):
    public_key = keypair.publickey().exportKey()
    public_out = open(public_keyfile, "wb")
    public_out.write(public_key)
    public_out.close()
    return


def read_public_key(public_keyfile):
    return RSA.importKey(open(public_keyfile).read())


def encrypt(public_key, plaintext_utf8):
    rsa = PKCS1_OAEP.new(public_key)   
    ciphertext_utf8 = rsa.encrypt(plaintext_utf8)
    return ciphertext_utf8


def decrypt(private_key, ciphertext_utf8):
    rsa = PKCS1_OAEP.new(private_key) 
    decryptedtext_utf8 = rsa.decrypt(ciphertext_utf8) 
    return decryptedtext_utf8