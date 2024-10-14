from charm.toolbox.pairinggroup import PairingGroup,GT
from charm.adapters.abenc_adapt_hybrid import HybridABEnc as HybridABEnc
from charm.schemes.abenc.abenc_waters09 import CPabe09
from charm.core.engine.util import objectToBytes, bytesToObject
import os 
def abe_decrypt(master_public_key_path, secret_key, cipher_text_path, decrypt_output_file_path):
    group = PairingGroup('SS512')
    cpabe = CPabe09(group)
    hyb_abe = HybridABEnc(cpabe, group)
    print("in decrypt")
    print("Secret Key is : ",secret_key)
    print()
    try:
        with open(master_public_key_path, 'rb') as f:
            master_public_key=bytesToObject(f.read(),group)
        
        with open(cipher_text_path, 'rb') as f:
            cipher_text=bytesToObject(f.read(),group)

        decrypted_msg = hyb_abe.decrypt(master_public_key, secret_key, cipher_text)
        if os.path.exists(decrypt_output_file_path):
             os.remove(decrypt_output_file_path)
        with open(decrypt_output_file_path, 'wb') as f:
            f.write(decrypted_msg)
        return "File Decrypted successfully.", decrypt_output_file_path, cipher_text_path
    
    except Exception as e:
        print("Exception Occured :",e)
        return "Exception Occured :",e