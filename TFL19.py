'''
Yi-Fan Tseng, Chun-I Fan, Zi-Cheng Liu
 
| From: "Fast Keyword Search Over Encrypted Data with Short Ciphertext in Clouds"
| Published in: 
| Available from: 
| Notes: Security Assumption: DBDH on asymmetric paring group. 

* type:           SE from KPABE
* setting:        Pairing

:Authors:    Yi-Fan Tseng
:Date:            08/30/2019
'''
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.hash_module import Waters, Hash
import time

debug = False
class TFL19(ABEnc):
    
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, debug)        
        group = groupObj

    def setup(self):
        g1, g2 = group.random(G1), group.random(G2)
        alpha, beta, phi, m = group.random(), group.random(), group.random(), group.random(GT)      
        h = g1 ** phi
        h_hat = g2 ** phi
        U = pair(g1, g2) ** (alpha * (beta - 1))
        V = pair(g1, g2) ** (alpha * beta)
               
        pk = {'g1':g1, 'g2':g2, 'U':U, 'V':V, 'h':h, 'm':m}
        msk = pk.copy()
        msk["g_hat^alpha"] = g2 ** alpha
        msk["h_hat"] = h_hat
        self.msk = msk

        return (msk, pk)

    def s_keygen(self, pk):
        return (pk, self.msk)

    def encrypt(self, pk, Attribute):
        H = Hash(group)
        k = group.random()

        CT = dict()
        CT["M"] = pk["m"]
        CT["C1"] = pk["m"] * pk["V"]** k
        CT["C2"] = pk["U"] ** k
        CT["C3"] = pk["g1"] ** k

        for name, value in Attribute.items():
            r = H.hashToZr(name + value)
            CT[name] = (pk["h"] * pk["g1"] ** r)**k
        
        return CT
    
    def keygen(self, msk, pk, Pol, Pol_M):
        H = Hash(group)
        SK = list()
        s, y2, y3 = 1, group.random(), group.random()
        yVector = [s] + [group.random() for i in range(len(Pol)-1)]

        sigma = dict()
        for dictEntryP in Pol:
            name, value = next(iter(dictEntryP.items()))
            h = H.hashToZr(name + value)
            sigma[name] = msk["h_hat"] * msk["g2"]**h
        
        for dictEntryM in Pol_M:
            name, row = next(iter(dictEntryM.items()))
            #lamb = row[0] + row[1]*y2 + row[2]*y3
            lamb = 0
            for r, y in zip(row, yVector):
                lamb += r*y
            
            r = group.random()
            
            Q = dict()
            D0 = (msk["g_hat^alpha"]**lamb) * (sigma[name] ** r)
            D1 = msk["g2"]**r
            tmp = [en for en in Pol if name not in en]
            #del tmp[name]
            Q = []
            for j in tmp:
                nameAux, _ = next(iter(j.items()))
                Q.append(sigma[nameAux] ** r)
            SK.append({"D0":D0, "D1":D1, "Q":Q})

        return SK
    
    def keygen2(self, msk, pk, Pol, Pol_M, weights):
        H = Hash(group)
        SK = list()
        s, y2, y3 = 1, group.random(), group.random()
        yVector = [s] + [group.random() for i in range(len(Pol)-1)]

        sigma = dict()
        for dictEntryP in Pol:
            name, value = next(iter(dictEntryP.items()))
            h = H.hashToZr(name + value)
            sigma[name] = msk["h_hat"] * msk["g2"]**h
        
        for dictEntryM in Pol_M:
            name, row = next(iter(dictEntryM.items()))
            #lamb = row[0] + row[1]*y2 + row[2]*y3
            lamb = 0
            for r, y in zip(row, yVector):
                lamb += r*y
            
            r = group.random()
            
            Q = dict()
            D0 = (msk["g_hat^alpha"]**lamb) * (sigma[name] ** r)
            D1 = msk["g2"]**r
            tmp = [en for en in Pol if name not in en]
            #del tmp[name]
            Q = []
            for j in tmp:
                nameAux, _ = next(iter(j.items()))
                Q.append(sigma[nameAux] ** r)
            SK.append({"D0":D0, "D1":D1, "Q":Q})
        SK2 = list()
        for query in weights:
            L = numerator = denominator = 1
            for i in query:
                tmp = SK[i]["D0"]
                for j in query:
                    aux = j
                    if j > i:
                        aux -= 1
                    if j != i:
                        tmp *= SK[i]["Q"][aux]
                numerator *= tmp
                denominator *= SK[i]["D1"]
            SK2.append({'numerator':numerator, 'denominator':denominator})

        return SK2

    def decrypt2(self, pk, sk_s, SK, CT, Delta, weights = [[]]):
        for query, sk_i in zip(weights, SK):
            L = numerator = denominator = 1
            delta = [Delta[i] for i in query]
            for name in delta:
                L *= CT[name]

            Z = (pair(CT["C3"], sk_i['numerator'])) / (pair(L, sk_i['denominator']))
            m = CT["C1"] / (CT["C2"] * Z)
            if CT["M"] == m:
                return True
        return False


    def decrypt(self, pk, sk_s, SK, CT, Delta, weights = [[]]):
        for query in weights:
            L = numerator = denominator = 1
            delta = [Delta[i] for i in query]
            for name in delta:
                L *= CT[name]
            for i in query:
                tmp = SK[i]["D0"]
                for j in query:
                    aux = j
                    if j > i:
                        aux -= 1
                    if j != i:
                        tmp *= SK[i]["Q"][aux]
                numerator *= tmp
                denominator *= SK[i]["D1"]
            Z = (pair(CT["C3"], numerator)) / (pair(L, denominator))
            m = CT["C1"] / (CT["C2"] * Z)
            if CT["M"] == m:
                return True
        return False

    def test(self):
        a, a1 = group.random(G1,2)
        b, b1 = group.random(G2,2)
        n, n1 = group.random(ZR,2)
        start = time.time()
        c = pair(a, b)
        end = time.time()
        print('Pairing Time: ', (end - start)*1000)
        c1 = pair(a1, b1)
        start = time.time()
        a * n1
        end = time.time()
        print('Div Time: ', (end - start)*1000)
        return 

def main():
    #Get the eliptic curve with the bilinear mapping feature needed.
    groupObj = PairingGroup('MNT159')
    #groupObj = PairingGroup('BN254')
    #groupObj = PairingGroup('SS512')

    #Policy_Matrix = [{'School':[1, 1, 0]}, {"Pos":[0, -1, 0]}]
    #Policy = [{'School':"NSYSU"}, {"Pos":"Teacher"}]
    #Attribute = {"School":"NSYSU", "Pos":"Teacher"}
    #Weights = [[0, 1]]
    #Delta = ["School", "Pos"]
    Policy_Matrix = [{'col3': [1, 0]}, {'col0': [1, 1]}, {'col1': [0, -1]}]
    Policy = [{'col3': '0'}, {'col0': '4'}, {'col1': '0'}]
    Attribute = {'col0': '5', 'col1': '0', 'col2': '3', 'col3': '0', 'col4': '0'}
    Delta =  ['col3', 'col0', 'col1']
    Weights = [[1, 2], [0]]
    
    #test_time = 100

    kpabe = TFL19(groupObj)
    kpabe.test()
    (msk, pk) = kpabe.setup()
    #m = group.random(GT)
    start = time.time()
    CT = kpabe.encrypt(pk, Attribute)
    end = time.time()
    print("Encryption: ", (end - start)*1000)
    SK = kpabe.keygen2(msk, pk, Policy, Policy_Matrix, Weights)
    start = time.time()
    msg = kpabe.decrypt2(pk, "lixo", SK, CT, Delta, Weights)
    end = time.time()
    print("Decryption: ", (end - start)*1000)
    print(msg)


if __name__ == '__main__':
    debug = True
    main()
