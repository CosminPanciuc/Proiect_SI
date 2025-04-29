import random
import hashlib

p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563  
g = 2

def generate_private_key():
    return random.randint(2, p - 2)

def generate_public_key(private_key):
    return pow(g, private_key, p)

def compute_shared_secret(peer_public_key, private_key):
    return pow(peer_public_key, private_key, p)

def derive_aes_key(shared_secret):
    return hashlib.sha256(str(shared_secret).encode()).digest()[:16]