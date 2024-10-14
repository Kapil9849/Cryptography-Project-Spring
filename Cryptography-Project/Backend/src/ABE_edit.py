from charm.toolbox.pairinggroup import PairingGroup,GT
from charm.adapters.abenc_adapt_hybrid import HybridABEnc as HybridABEnc
from charm.schemes.abenc.abenc_waters09 import CPabe09
from charm.core.engine.util import objectToBytes, bytesToObject
from Encrypt_file import *
from generate_secret import *
from decrypt_file import *

# group = PairingGroup('SS512')
# cpabe = CPabe09(group)
# hyb_abe = HybridABEnc(cpabe, group)
# input_file = "../data/sample.txt"
# output_file = "../data/encrypted/encrypted_sample"
# decrypt_output_file= "../data/decrypted/decrypted_sample"
# key_output_file = "../data/keys/"
# Define the attributes for your users and policies
# For example, "Doctor", "Nurse", "Cardiology", "Pediatrics", etc.
# attributes = ['NURSE', 'CARDIOLOGY', 'ICI', '1245']

# # Define the access policy for the file
# policy_string = '(((DOCTOR) AND (CARDIOLOGY) AND (SURGEON) AND (12345)) OR ((NURSE) AND (CARDIOLOGY) AND (ICI) AND (1245)))'

# # Generating master public and private keys
# (master_secret_key, master_public_key) = hyb_abe.setup()

# # SToring master secret and master public into files
# with open(key_output_file + "mst.bin", 'wb') as f:
#     serialized_key = objectToBytes(master_secret_key,group)
#     f.write(serialized_key) 

# with open(key_output_file + "mpk.bin", 'wb') as f:
#     serialized_key = objectToBytes(master_public_key,group)
#     f.write(serialized_key)

# secret_key=generate_secret(master_public_key,master_secret_key,attributes)

# ENcrypting the file

# cipher_text=abe_encrypt(input_file,output_file,policy_string,key_output_file + "mpk.bin")
# print(cipher_text)
# # Decrypting the File
# decrypt=abe_decrypt(key_output_file+ "mpk.bin",secret_key,cipher_text[1], decrypt_output_file)
# print(decrypt)

class ABE_edit:
    def __init__(self,input_file,file_name,attributes,policy_string):
        print("Constructor called!")
        self.group = PairingGroup('SS512')
        self.cpabe = CPabe09(group)
        self.hyb_abe = HybridABEnc(cpabe, group)
        self.input_file = input_file
        self.file_name=file_name
        self.output_file = "../data/encrypted/"+file_name
        self.decrypt_output_file= "../data/decrypted/decrypted_"+file_name
        self.key_output_file = "../data/keys/"
        self.attributes = attributes 
        # Define the access policy for the file
        self.policy_string=policy_string
        # self.policy_string = '(((DOCTOR) AND (CARDIOLOGY) AND (SURGEON) AND (12345)) OR ((NURSE) AND (CARDIOLOGY) AND (ICI) AND (1245)))'
    
    def generate_keys(self):
        
        with open(self.key_output_file + "mpk.bin", 'rb') as f:
            master_public_key=bytesToObject(f.read(),group)
        
        with open(self.key_output_file + "mst.bin", 'rb') as f:
            master_secret_key=bytesToObject(f.read(),group)
        
        self.secret_key=generate_secret(master_public_key,master_secret_key,self.attributes)
        return self.secret_key
    
    def encryption(self):

        # ENcrypting the file
        cipher_text=abe_encrypt(self.input_file,self.output_file,self.policy_string,self.key_output_file + "mpk.bin")
        print(cipher_text)
        return cipher_text
    
    def decryption(self,cipher_text_path,secret_key):
        # Decrypting the File
        decrypt=abe_decrypt(self.key_output_file+ "mpk.bin",secret_key,cipher_text_path, self.decrypt_output_file)
        print(decrypt)
        return decrypt