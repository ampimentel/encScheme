'''
Dong Jin Park, Kihyun Kim, and Pil Joong Lee

| From: ""
| Published in: 
| Available from: 
| Notes: Security Assumption:

* type:           
* setting:        Pairing

:Authors:    Afonsinho Pimentel
:Date:            05/07/2022
'''
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1, G2, GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.hash_module import Hash
import time

debug = False
class TestOp(ABEnc):
    
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, debug)        
        group = groupObj

    
    def test(self, count):
        a = group.random(ZR)
        b, b1 = group.random(G1, 2)
        c = group.random(G2)
        
        t_p, t_mg, t_ms = 0, 0, 0
        for i in range(count):
            start = time.time()
            pair(c, b)
            end = time.time()
            t_p += (end - start)*1000 / count
            start = time.time()
            t1 = a * b
            end = time.time()
            t_mg += (end - start)*1000  / count
            start = time.time()
            t2 = b ** a
            end = time.time()
            t_ms += (end - start)*1000  / count
        
        return t_p, t_mg, t_ms

def main():
    #Get the eliptic curve with the bilinear mapping feature needed.
    #groupObj = PairingGroup('BN254')
    groupObj = PairingGroup('SS512')

    
    kpabks = TestOp(groupObj)
    print(kpabks.test(100))
    

if __name__ == '__main__':
    debug = True
    main()