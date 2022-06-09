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
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1, G2, GT,pair
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
            CT[name] = pair(pk["Y1"], r*group.hash(name + value, G2))
        #print(CT)
        return CT
    
    #assumptions: Pol and Pol_M are a list of dicts with the same number of entries and matching keyword names
    def keygen(self, msk, pk_s, Pol, Pol_M, weights = [[]]):
        sums = []
        u = group.random(ZR)
        aux = msk["s1"] / ( msk["s2"] + u)
        for dictEntryP in Pol:
            name, val = next(iter(dictEntryP.items())) #get entry form dict => key:row
            sums.append(group.hash(name + val, G2) * aux)
        T2 = u
        T1 = []
        for query in weights:
            sumT1 = 0
            first = True
            for i in query:
                if first:
                    sumT1 = sums[i]
                    first = False
                else:
                    sumT1 += sums[i]
            T1.append(sumT1)
        return {"T1" : T1, "T2":T2}

    def decrypt(self, pk, sk_s, SK, CT, Delta, weights = [[]]):
        
        for conjSearch, sumT1 in zip(weights, SK["T1"]):
            delta = [Delta[i] for i in conjSearch]
            #one conjunctive search
            mult = 1
            for name in delta:
                mult *= CT[name]
            
            if mult == pair(CT["B"] + SK["T2"]*CT["C"], sumT1):
                return True
        return False

    def test(self):
        a = group.random(ZR)
        b, b1 = group.random(G1, 2)
        c = group.random(G2)
        start = time.time()
        pair(c, b)
        end = time.time()
        print('Pairing Time: ', (end - start)*1000)
        start = time.time()
        t1 = a * b
        end = time.time()
        print('Mult Time: ', (end - start)*1000)
        start = time.time()
        t2 = b ** a
        end = time.time()
        print('Exp Time: ', (end - start)*1000)
        start = time.time()
        t2 = b * b1
        end = time.time()
        print('Div Time: ', (end - start)*1000)
        return 

def main():
    #Get the eliptic curve with the bilinear mapping feature needed.
    groupObj = PairingGroup('MNT159')
    #groupObj = PairingGroup('SS512')

    #print(groupObj.Pairing)
    #Policy_Matrix = [{'School':[1, 1, 0]}, {"Pos":[0, -1, 0]}]
    #Policy = [{'School':"NSYSU"}, {"Pos":"Teacher"}]
    #Keyword = {"School":"NSYSU", "Pos":"Teacher"}
    #Delta = ["School", "Pos"]
    #Weights = [[0, 1]]
    Policy_Matrix = [] 
    Policy = [{'col0': '4'}, {'col1': '0'}, {'col3' : '5'}]
    Keyword = {'col0': '5', 'col1': '0', 'col2': '3', 'col3': '0', 'col4': '0'}
    Delta = ['col0', 'col1', 'col3']
    Weights = [[0, 1], [2]]
    
    kpabks = PECK(groupObj)
    kpabks.test()
    (msk, pk) = kpabks.setup()
    (pk_s, sk_s) = kpabks.s_keygen(pk)
    #print(kpabks.test(pk))
    CT = kpabks.encrypt(pk, Keyword)
    SK = kpabks.keygen(msk, pk_s, Policy, Policy_Matrix,Weights)
    
    start = time.time()
    tmp = kpabks.decrypt(pk, sk_s, SK, CT, Delta, Weights)
    end = time.time()
    print("Decryption: ", (end - start) * 1000)
    print(tmp)

if __name__ == '__main__':
    debug = True
    main()

