from json import dumps
import base64
from datetime import datetime
import uuid
from ellipticcurveLoc.ecdsaLoc import EcdsaLoc
from ellipticcurveLoc.privateKey import PrivateKey
from ellipticcurveLoc.curve import secp256k1, getCurveByOid
from ellipticcurveLoc.ecdsa import Ecdsa
from ellipticcurveLoc.privateKey import PrivateKey
#import ellipticcurveLoc.ecdsaLoc
#import ellipticcurveLoc.privateKey
from hashlib import sha256, sha3_512
from ellipticcurveLoc.signature import Signature
import time
from ellipticcurveLoc.math import Math
import pyaes
import aes, os

import random



class Barusz:
    
    def __init__(self, userNumber, locationOP, PinCode="000000"):
        self.userNumber  = userNumber
        rd = random.Random()
        rd.seed(self.userNumber)
        self.uuidStr = str(uuid.UUID(int=rd.getrandbits(128)))#uuid.UUID(rd.getrandbits(128))) # uuid1()) 
        self.locationTagStr = self.getLocationTag(locationOP)
        self.secretStr = PinCode #sha256(PinCode.encode('utf-8')).hexdigest()
        self.timeCreatedStr =  (datetime.now()).strftime("%H:%M:%S")+", " + datetime.today().strftime("%B %d, %Y")
        self.registry = "\nUUID : " + self.uuidStr + "\nLocationTag: " + self.locationTagStr + "\nSecret: " + self.secretStr +  "\nCreated Time: " + self.timeCreatedStr + "\n"
        print("\nRegistration Detail = ", self.registry)
        self.rootKey = sha3_512(self.registry.encode('utf-8')).hexdigest()
        #print("Root Key : ",self.rootKey)
        self.privateKey =  PrivateKey(int(self.rootKey,16))
        self.publicKey = self.privateKey.publicKey()
        print("PrivateKey  = ",self.privateKey.toString())
        print("PublicKey   = ",self.publicKey .toString())
        

    def getLocationTag(self, locationOPStr):
        print("With Location OP Code : ",locationOPStr)
        locationOP_string_bytes = locationOPStr.encode("ascii")  
        location_base64_bytes = base64.b64encode(locationOP_string_bytes)
        location_base64_string = location_base64_bytes.decode("ascii")
        print(f"Location Encoded string: {location_base64_string}")
        return location_base64_string

    def getLocationOP(self, locationTagStr): 
        print("With Location Tag Code : ",locationTagStr)   
        locationTag_base64_bytes = locationTagStr.encode("ascii")
        locationOP_bytes = base64.b64decode(locationTag_base64_bytes)
        locationOPStr = locationOP_bytes.decode("ascii")
        print(f"Location Decoded string: {locationOPStr}")
        return locationOPStr

def runbarusz():
    locationOP = "8Q8999F8+J799C6+V5"
    print("Barusz is Starting!!! .....")
    userAlice = Barusz(1,locationOP)
    userBob   = Barusz(2,locationOP, "123456")
    if(locationOP == userAlice.getLocationOP(userAlice.locationTagStr)):
        print("Location Match is Successfully !!!")
    else:
        print("Location Match is NOT Successfully !!!")

if __name__ == '__main__':
    runbarusz()