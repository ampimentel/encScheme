'''
Dong Jin Park, Kihyun Kim, and Pil Joong Lee

| From: "Public Key Encryption with Conjunctive Field Keyword Search"
| Published in: 
| Available from: 
| Notes: Security Assumption:

* type:           SE supporting conjunctive search query
* setting:        Pairing

:Authors:    Afonsinho Pimentel
:Date:            03/06/2022
'''
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.hash_module import Hash
import time

debug = False
class PECK(ABEnc):
    
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, debug)        
        group = groupObj

    def setup(self):
        P = group.random(G1)
        s1, s2 = group.random(ZR, 2) #Zp
        Y1 = s1 * P
        Y2 = s2 * P
        Apub = {"P" : P, "Y1": Y1, "Y2" : Y2}
        Apriv = {"s1" : s1, "s2" : s2}
        self.Apriv = Apriv
        return (Apriv, Apub)

    def s_keygen(self, pk):
        return (pk, self.Apriv)

    def encrypt(self, pk, Keyword):
        r = group.random(ZR)
        CT = dict()
        CT["B"] = r * pk["Y2"]
        CT["C"] = r * pk["P"]

        for name, value in Keyword.items():
            CT[name] = pair(r*group.hash(value, G1), pk["Y1"])
        #print(CT)
        return CT
    
    #assumptions: Pol and Pol_M are a list of dicts with the same number of entries and matching keyword names
    def keygen(self, msk, pk_s, Pol, Pol_M):
        T1 = []
        u = group.random(ZR)
        aux = msk["s1"] / ( msk["s2"] + u)
        for dictEntryP in Pol:
            _, val = next(iter(dictEntryP.items())) #get entry form dict => key:row
            T1.append(group.hash(val, G1) * aux)
        T2 = u
        
        return {"T1" : T1, "T2":T2}

    def decrypt(self, pk, sk_s, SK, CT, Delta, weights = [[]]):
        
        for conjSearch in weights:
            delta = [Delta[i] for i in conjSearch]
            #one conjunctive search
            mult = 1
            for name in delta:
                mult *= CT[name]
            sumT1 = 0
            first = True
            for i in conjSearch:
                if first:
                    sumT1 = SK["T1"][i]
                    first = False
                else:
                    sumT1 += SK["T1"][i]
            if mult == pair(sumT1, CT["B"] + SK["T2"]*CT["C"]):
                return True
        return False

    def test(self, pk):
        a, b = group.random(ZR, 2)
        U, V = group.random(G1, 2)
        res1 = pair(a*U, b*V) 
        U *= 1
        return res1 == pair(U, V)**(a*b)

        

def main():
    #Get the eliptic curve with the bilinear mapping feature needed.
    #groupObj = PairingGroup('MNT224')
    groupObj = PairingGroup('SS512')
    #print(groupObj.Pairing)
    #Policy_Matrix = [{'School':[1, 1, 0]}, {"Pos":[0, -1, 0]}]
    #Policy = [{'School':"NSYSU"}, {"Pos":"Teacher"}]
    #Keyword = {"School":"NSYSU", "Pos":"Teacher"}
    #Delta = ["School", "Pos"]
    #Weights = [[0, 1]]
    Policy_Matrix = [] 
    Policy = [{'col3': '4'}, {'col2': '10'}, {'col0': '8'}, {'col1': '9'}]
    Keyword = {'col0': '2', 'col1': '6', 'col2': '9', 'col3': '4', 'col4': '7', 'col5': '1', 'col6': '1', 'col7': '8', 'col8': '0', 'col9': '1'}
    Delta = ['col3', 'col2', 'col0', 'col1']
    Weights = [[2, 3, 1], [0]]
    
    kpabks = PECK(groupObj)

    (msk, pk) = kpabks.setup()
    (pk_s, sk_s) = kpabks.s_keygen(pk)
    #print(kpabks.test(pk))
    CT = kpabks.encrypt(pk, Keyword)
    SK = kpabks.keygen(msk, pk_s, Policy, Policy_Matrix)
    
    start = time.time()
    tmp = kpabks.decrypt(pk, sk_s, SK, CT, Delta, Weights)
    end = time.time()
    print("Decryption: ", (end - start)*1000)
    print(tmp)

if __name__ == '__main__':
    debug = True
    main()

