from atexit import register
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
    
    def __init__(self,  locationOP, secretStr="Unknown"):
        print("\n.......................START.................................")
        self.curve = secp256k1
        self.secretStr = secretStr
        self.uuidStr = "NULL"#str(uuid.UUID(int=rd.getrandbits(128)))#uuid.UUID(rd.getrandbits(128))) # uuid1()) 
        self.locationTagStr = self.getLocationTag(locationOP)
        self.nfcCardUIDStr = "NULL"#nfcCardUID #sha256(PinCode.encode('utf-8')).hexdigest()
        self.timeCreatedStr =  (datetime.now()).strftime("%H:%M:%S")+", " + datetime.today().strftime("%B %d, %Y")
        self.keyStr = self.secretStr + self.locationTagStr
        self.registry = "\nUUID : " + self.uuidStr + "\nLocationTag: " + self.locationTagStr + "\nNFC Card UID: " + self.nfcCardUIDStr +  "\nCreated Time: " + self.timeCreatedStr + "\n"
        print("\nUser Creation Detail : \n", self.registry)
        
   
        print("\n.......................END.................................")
        

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

    def registerUser(self, userNumber, nfcCardUIDStr="0x00000000"):
        rd = random.Random()
        rd.seed(userNumber)
        curve = secp256k1
        uuidStr = str(uuid.UUID(int=rd.getrandbits(128)))
        rootCardKey = sha3_512((nfcCardUIDStr+uuidStr).encode('utf-8')).hexdigest()
        #print("Root Key : ",self.rootKey)
        privateCardKey =  PrivateKey(int(rootCardKey,16))
        publicCardKey = privateCardKey.publicKey()
        print("UUID: (private) : ", uuidStr)
        print("NFC Card UID (Public) : ", nfcCardUIDStr)
        print("\nServer PrivateCardKey  = ",privateCardKey.toString())
        print("Server PublicCardKey   = ",publicCardKey .toString())
        return uuidStr, nfcCardUIDStr

    def getUserRegistry(self):
        self.registry = "\nUUID : " + self.uuidStr + "\nLocationTag: " + self.locationTagStr + "\nNFC Card UID: " + self.nfcCardUIDStr +  "\nCreated Time: " + self.timeCreatedStr + "\n"
        print("\nUser Creation Detail : \n", self.registry)
    
    def generateKeyPairs(self):
        self.rootKey = sha3_512((self.keyStr + self.uuidStr).encode('utf-8')).hexdigest()
        #print("Root Key : ",self.rootKey)
        self.privateKey =  PrivateKey(int(self.rootKey,16))
        self.publicKey = self.privateKey.publicKey()
        print("\nPrivateKey  = ",self.privateKey.toString())
        print("PublicKey   = ",self.publicKey .toString())
        self.rootCardKey = sha3_512((self.nfcCardUIDStr+self.uuidStr).encode('utf-8')).hexdigest()
        self.privateCardKey =  PrivateKey(int(self.rootCardKey,16))
        self.publicCardKey = self.privateCardKey.publicKey()
        print("\nPrivateCardKey  = ",self.privateCardKey.toString())
        print("PublicCardKey   = ",self.publicCardKey .toString())
        self.secretUserKey = (Math.multiply(self.publicCardKey.point, self.privateKey.secret % self.curve.N, N=self.curve.N, A=self.curve.A, P=self.curve.P)).x
        self.secretCardKey = (Math.multiply(self.publicKey.point, self.privateCardKey.secret % self.curve.N, N=self.curve.N, A=self.curve.A, P=self.curve.P)).x 
        print("\nSecret User Key : ",self.secretUserKey)
        print("\nSecret Card Key : ",self.secretCardKey)
        
        
        

def runbarusz():
    locationOP = "8Q8999F8+J799C6+V5"
    cardsRegistered = ["0x437DFB03", "0x0BC250F9" , "0x8346FC03", "0x9670FC03", "0xEB3EBB1F"]
    print("Barusz is Starting!!! .....")
    userAlice = Barusz(locationOP)
    userAlice.uuidStr, userAlice.nfcCardUIDStr = userAlice.registerUser(1, "0x437DFB03")
    userAlice.getUserRegistry()
    userAlice.generateKeyPairs()
    #userBob   = Barusz(2,locationOP, cardsRegistered[2])
    if(locationOP == userAlice.getLocationOP(userAlice.locationTagStr)):
        print("Location Match is Successfully !!!")
    else:
        print("Location Match is NOT Successfully !!!")

if __name__ == '__main__':
    runbarusz()