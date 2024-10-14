from charm.toolbox.pairinggroup import PairingGroup,GT
from charm.adapters.abenc_adapt_hybrid import HybridABEnc as HybridABEnc
from charm.schemes.abenc.abenc_waters09 import CPabe09
from charm.core.engine.util import objectToBytes, bytesToObject
import os
def abe_encrypt(input_file_path,output_file_path,policy,master_public_key_path):
    group = PairingGroup('SS512')
    cpabe = CPabe09(group)
    hyb_abe = HybridABEnc(cpabe, group)
    print("in encrypt")
    try:
        with open(input_file_path, 'rb') as f:
                file_data = f.read()

        with open(master_public_key_path, 'rb') as f:
            master_public_key=bytesToObject(f.read(),group)

        cipher_text = hyb_abe.encrypt(master_public_key, file_data, policy)
        print("CIpher text is : ",cipher_text)
        print()
        if os.path.exists(output_file_path[:len(output_file_path)-4] + "_ct.bin"):
             os.remove(output_file_path[:len(output_file_path)-4] + "_ct.bin")

        with open(output_file_path[:len(output_file_path)-4] + "_ct.bin", 'wb') as f:
            serialized_key = objectToBytes(cipher_text,group)
            f.write(serialized_key)
        # return cipher_text
        return "File Encrypted and saved successfully.",output_file_path[:len(output_file_path)-4] + "_ct.bin"
    except Exception as e:
        return "Exception Occured during Excryption: ",e
    

    