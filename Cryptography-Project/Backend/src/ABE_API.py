import json
import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict
import random
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi.middleware.cors import CORSMiddleware
from ABE_edit import *

app = FastAPI()
roles=["Doctor","Nurse"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
class UserWithoutPassword(BaseModel):
    id: int
    username: str
    first_name: str
    last_name: str
    role: str
    department: str
    specialization: str = None

class LoginModel(BaseModel):
    username:str
    password:str
# Endpoint to get users
@app.get("/users", response_model=List[UserWithoutPassword])
def get_users():
    with open("../data/files/users.json", 'rb') as f:
        user_data = json.load(f)
    return user_data

@app.post("/login")
def Login(userdata:LoginModel):
    with open("../data/files/users.json", 'rb') as f:
        user_data = json.load(f)
    for user in user_data:
        if(user["username"]==userdata.username):
            if(user["password"]==userdata.password):
                del user["password"]
                return {"result":True,"data":user}
            else:
                return {"result":False,"message":"Invalid user credentials"}
    else:
        return {"result":False, "message":"User not found."}

@app.get("/getfiles/{role}")
def get_files(role:str):
    if(role is not None and (role in roles)):
        files = os.listdir("../data/medical_records/"+role)
        return {"result":True, "data":files}
    else:
        return {"result":False, "message":"Invalid Role."}

class accessModel(BaseModel):
    user_id:int
    file_name:str

def checkIfUserHasAccess(file_data:accessModel):
    with open("../data/files/user_access.json", 'rb') as f:
        user_access_data = json.load(f)
    for i in user_access_data:
        if(i["id"]==file_data.user_id):
            if(file_data.file_name in i["files"]):
                return True
            else:
                return False

def encryptFile(input_file_path,file_name,attributes):
    policy_string=generatePolicyString(attributes, file_name)
    print("Generated policy string",policy_string)
    abe_obj=ABE_edit(input_file_path,file_name,attributes,policy_string)
    # secret_key=abe_obj.generate_keys()
    cipher_text=abe_obj.encryption()
    print(cipher_text)
    # decrypt_message=abe_obj.decryption(cipher_text[1],secret_key)
    # print(decrypt_message)
    if(len(cipher_text)==2):
        return True
    return False

def decryptFile(input_file_path,file_name,attributes):
    policy_string=getPolicyString(file_name)
    print("policy string",policy_string)
    abe_obj=ABE_edit(input_file_path,file_name,attributes,policy_string)
    secret_key=abe_obj.generate_keys()
    cipher_text_path="../data/encrypted/"+file_name[:len(file_name)-4]+"_ct.bin"
    decrypt_message=abe_obj.decryption(cipher_text_path,secret_key)
    return decrypt_message

def getPolicyString(file_name):
    with open("../data/files/file_data.json", 'rb') as f:
        file_data = json.load(f)
    for i in file_data:
        if(i["file_name"]==file_name):
            print("file exists with policy string",i["policy_string"])
            return i["policy_string"]
    else:
        return "Error"
def generatePolicyString(attributes,file_name):
    new_policy_string=""
    with open("../data/files/file_data.json", 'rb') as f:
        file_data = json.load(f)
    print(file_data)
    for i in file_data:
        if(i["file_name"]==file_name):
            print("file exists with policy string",i["policy_string"])
            new_policy_string=createPolicyString(i["policy_string"],attributes)
            i["policy_string"]=new_policy_string
            with open("../data/files/file_data.json", 'w') as file:
                json.dump(file_data, file, indent=4)
            break
    else:
        print("file doesnt not have a policy string")
        new_policy_string=createPolicyString("",attributes)
        obj={"file_name":file_name,"policy_string":new_policy_string}
        file_data.append(obj)
        with open("../data/files/file_data.json", 'w') as file:
            json.dump(file_data, file, indent=4)
    return new_policy_string

def createPolicyString(policystring,attributes):
    policy=""
    attr=[]
    if(policystring==""):
        for i in attributes:
            attr.append("("+str(i).upper()+")")
        policy="("+"("+' AND '.join(attr)+")"+")"
        print(policy)
    else:
        sample=""
        for i in attributes:
            attr.append("("+str(i).upper()+")")
        sample="("+' AND '.join(attr)+")"
        policy=policystring[:len(policystring)-1]+" OR "+ sample+ ")"
        print(policy)
    return policy

def removeRequest(data:accessModel):
    print(data)
    with open("../data/files/request_access.json", 'rb') as f:
        request_data = json.load(f)
    for i in request_data:
        if(i["user_id"]==data.user_id):
            print(i)
            if(data.file_name in i["requests"]):
                print("file is in there")
                i["requests"].remove(data.file_name)
                with open("../data/files/request_access.json", 'w') as file:
                    json.dump(request_data, file, indent=4)
@app.post("/reject")
def removeAccess(data:accessModel):
    print(data)
    with open("../data/files/request_access.json", 'rb') as f:
        request_data = json.load(f)
    for i in request_data:
        if(i["user_id"]==data.user_id):
            print(i)
            if(data.file_name in i["requests"]):
                print("file is in there")
                i["requests"].remove(data.file_name)
                with open("../data/files/request_access.json", 'w') as file:
                    json.dump(request_data, file, indent=4)
    return {"result":True,"message":"Request Rejected Successfully"}
@app.post("/giveaccess")
def give_access(data:accessModel):
    attributes=[]
    current_user={}
    with open("../data/files/users.json", 'rb') as f:
        user_data = json.load(f)
    for user in user_data:
        if(user["id"]==data.user_id):
            attributes.append(str(user["id"]).upper())
            attributes.append(str(user["role"]).upper())
            attributes.append(str(user["department"]).upper())
            attributes.append(str(user["specialization"]).upper())
            current_user=user
            break
    input_file_path="../data/medical_records/"+current_user["role"]+"/"+data.file_name

    hasaccess=checkIfUserHasAccess(data)
    if(hasaccess):
        print("User has access")
        removeRequest(data)
        return {"result":True,"message": "User already has access to this file."}
    else:
        with open("../data/files/user_access.json", 'rb') as f:
            user_access_data = json.load(f)
        for i in user_access_data:
            if(i["id"]==data.user_id):
                i["files"].append(data.file_name)
                with open("../data/files/user_access.json", 'w') as file:
                    json.dump(user_access_data, file, indent=4)
                status=encryptFile(input_file_path,data.file_name,attributes)
                break
        else:
            obj={"id":data.user_id,"files":[data.file_name]}
            user_access_data.append(obj)
            print("New user", user_access_data)
            with open("../data/files/user_access.json", 'w') as file:
                json.dump(user_access_data, file, indent=4)
            status=encryptFile(input_file_path,data.file_name,attributes)
        removeRequest(data)
    

    return {"result":status,"message": "Access is provided"}

@app.post("/requestaccess")
def request_access(data:accessModel):
    with open("../data/files/request_access.json", 'rb') as f:
        request_data = json.load(f)
    for i in request_data:
        if(i["user_id"]==data.user_id):
            if(data.file_name in i["requests"]):
                return {"result":False,"message":"Request already submitted"}
            else:
                i["requests"].append(data.file_name)
                with open("../data/files/request_access.json", 'w') as file:
                    json.dump(request_data, file, indent=4)
                return {"result":True,"message":"Requested Successfully"}
    else:
        obj={"user_id":data.user_id,"requests":[data.file_name]}
        request_data.append(obj)
        with open("../data/files/request_access.json", 'w') as file:
            json.dump(request_data, file, indent=4)
        return {"result":True,"message":"Requested Successfully"}

@app.post("/getfile")
def get_file(data:accessModel):
    attributes=[]
    current_user={}
    with open("../data/files/users.json", 'rb') as f:
        user_data = json.load(f)
    for user in user_data:
        if(user["id"]==data.user_id):
            attributes.append(str(user["id"]).upper())
            attributes.append(str(user["role"]).upper())
            attributes.append(str(user["department"]).upper())
            attributes.append(str(user["specialization"]).upper())
            current_user=user
            break
    input_file_path="../data/medical_records/"+current_user["role"]+"/"+data.file_name

    hasaccess=checkIfUserHasAccess(data)
    if(hasaccess):
        print("User has access")
        decrypted_data= decryptFile(input_file_path,data.file_name,attributes)
        f=open(decrypted_data[1], 'r')
        file_data = f.read().splitlines()
        f=open(decrypted_data[2], 'r')
        cipher_text=f.read()
        return {"result":decrypted_data[0],"message":file_data,"cipher_text":cipher_text}
    else:
        return {"result":"False","message": "Access Denied !"}

@app.get("/accessinfo")
def getAccessInfo(user_id:int):
    with open("../data/files/user_access.json", 'rb') as f:
        user_data = json.load(f)
    for i in  user_data:
        if(i["id"]==user_id):
            return {"result":True,"files":i["files"]}
    else:
        return {"result":True,"files":[]}

@app.get("/allaccessinfo")
def getAllAccessInfo():
    with open("../data/files/request_access.json", 'rb') as f:
        user_data = json.load(f)
    return {"result":True,"files":user_data}

def updatePolicyToRemoveAccess(file_name,attributes):
    attr=[]
    for i in attributes:
        attr.append("("+str(i).upper()+")")
    policy="("+' AND '.join(attr)+")"
    return policy

@app.post("/removeAccess")
def removeAccess(data:accessModel):
    attributes=[]
    current_user={}
    with open("../data/files/user_access.json", 'rb') as f:
        user_data = json.load(f)
    for user in user_data:
        if(user["id"]==data.user_id):
            if(data.file_name in user["files"]):
                (user["files"]).remove(data.file_name)
                with open("../data/files/user_access.json", 'w') as file:
                    json.dump(user_data, file, indent=4)
                    break
    with open("../data/files/users.json", 'rb') as f:
        user_data = json.load(f)
    for user in user_data:
        if(user["id"]==data.user_id):
            attributes.append(str(user["id"]).upper())
            attributes.append(str(user["role"]).upper())
            attributes.append(str(user["department"]).upper())
            attributes.append(str(user["specialization"]).upper())
            current_user=user
            break
    policystring=updatePolicyToRemoveAccess(data.file_name,attributes)
    print("returned string",policystring)
    with open("../data/files/file_data.json", 'rb') as f:
        file_data = json.load(f)
    for file in file_data:
        if(file["file_name"]==data.file_name):
            originalps=file["policy_string"][1:-1]
            print(originalps.split(" OR "))
            split_data=originalps.split(" OR ")
            if(policystring in split_data):
                split_data.remove(policystring)
            print("after remove : ",split_data)
            final_string="("+' OR '.join(split_data)+")"
            print("final :",final_string)
            file["policy_string"]=final_string
            with open("../data/files/file_data.json", 'w') as file:
                json.dump(file_data, file, indent=4)
            return {"result":True,"message":"Access revoked successfully!"}
    return {"result":False,"message":"Access revoke Failed!"}
    
            
    
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)