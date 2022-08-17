from hashlib import sha256, sha3_512
from .signature import Signature
from .math import Math
from .utils.integer import RandomInteger
from .utils.binary import numberFromByteString
from .utils.compatibility import *


class EcdsaLoc:

    @classmethod
    def sign(cls, message, privateKey, hashfunc=sha3_512):
        byteMessage = hashfunc(toBytes(message)).digest()
        numberMessage = numberFromByteString(byteMessage)
        print("ESDALOC - Print Private Key : ", privateKey.toString())
        curve = privateKey.curve
        Base = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffFffffffff
        loc = 0xf10f3df7d17cf89e
        locHex  = 0xf10f3df7d17cf89e000000000000000000000000000000000000000000000000
        #lochash = hashfunc(toBytes(loc)).digest()
        r, s, randSignPoint = 0, 0, None
       # while r == 0 or s == 0:
        randNum = RandomInteger.between(1, curve.N - 1)#privateKey.secret#loc#numberFromByteString(lochash)#RandomInteger.between(1, curve.N - 1) mod(loc)
        #print("....................Location Number ..................[",randNum,"]....\n")
        randSignPoint = Math.multiply(curve.G, n=randNum, A=curve.A, P=curve.P, N=curve.N)
        r = randSignPoint.x % curve.N
        s = ((numberMessage + r * privateKey.secret) * (Math.inv(randNum, curve.N))) % curve.N
        if (r == 0 or s == 0):
            print("Flag raised !!! (r == 0 or s == 0)")
        recoveryId = randSignPoint.y & 1
        if randSignPoint.y > curve.N:
            recoveryId += 2

        return Signature(r=r, s=s, recoveryId=recoveryId)

    @classmethod
    def verify(cls, message, signature, publicKey, hashfunc=sha3_512):
        byteMessage = hashfunc(toBytes(message)).digest()
        numberMessage = numberFromByteString(byteMessage)
        curve = publicKey.curve
        r = signature.r
        s = signature.s
        if not 1 <= r <= curve.N - 1:
            return False
        if not 1 <= s <= curve.N - 1:
            return False
        inv = Math.inv(s, curve.N)
        u1 = Math.multiply(curve.G, n=(numberMessage * inv) % curve.N, N=curve.N, A=curve.A, P=curve.P)
        u2 = Math.multiply(publicKey.point, n=(r * inv) % curve.N, N=curve.N, A=curve.A, P=curve.P)
        v = Math.add(u1, u2, A=curve.A, P=curve.P)
        if v.isAtInfinity():
            return False
        return v.x % curve.N == r
