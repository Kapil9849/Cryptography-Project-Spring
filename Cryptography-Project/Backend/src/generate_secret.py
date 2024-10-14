from charm.toolbox.pairinggroup import PairingGroup,GT
from charm.adapters.abenc_adapt_hybrid import HybridABEnc as HybridABEnc
from charm.schemes.abenc.abenc_waters09 import CPabe09
from charm.core.engine.util import objectToBytes, bytesToObject
from Encrypt_file import *
group = PairingGroup('SS512')
cpabe = CPabe09(group)
hyb_abe = HybridABEnc(cpabe, group)
def generate_secret(master_public_key, master_secret_key, attributes):
    # Generating Secret for the user on demand
    secret_key = hyb_abe.keygen(master_public_key, master_secret_key, attributes)

    return secret_key