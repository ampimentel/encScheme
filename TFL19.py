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

    def decrypt2(self, pk, sk_s, SK, CT, Delta, weights = [[]]):
        
        L = numerator = denominator = 1
        for name in Delta:
            L *= CT[name]
        #numerator = []
        #denominator = []
        #print(len(SK))
        for name, sk_name in zip(Delta, SK):
            tmp = sk_name["D0"]
            #T = Delta.copy()
            #T.remove(name)
            #PROBLEMA: NUMERADOR TEM Q SER CALCULADO SOBRE UM SUBESPAÇO DE de delta
            
            for item in sk_name["Q"]:
                tmp *=  item
            print(tmp)
            numerator.append(tmp)
            denominator.append(sk_name["D1"])
        
        for query in [[0]]:
            num = den = L = 1
            for wi in query:
                L *= CT[Delta[wi]]
                num*=numerator[wi]
                den*=denominator[wi]
            #print(num)
            Z = (pair(CT["C3"], num)) / (pair(L, den))
            m = CT["C1"] / (CT["C2"] * Z)
            if CT["M"] == m:
                return True
        return False 
        
            

def main():
    #Get the eliptic curve with the bilinear mapping feature needed.
    #groupObj = PairingGroup('MNT224')
    groupObj = PairingGroup('BN254')
    #Policy_Matrix = [{'School':[1, 1, 0]}, {"Pos":[0, -1, 0]}]
    #Policy = [{'School':"NSYSU"}, {"Pos":"Teacher"}]
    #Attribute = {"School":"NSYSU", "Pos":"Teacher"}
    #Weights = [[0, 1]]
    #Delta = ["School", "Pos"]
    Policy_Matrix = [{'col3': [1, 0, 0]}, {'col2': [0, -1, 0]}, {'col0': [1, 1, 1]}, {'col1': [0, 0, -1]}]
    Policy = [{'col3': '4'}, {'col2': '10'}, {'col0': '8'}, {'col1': '9'}]
    Attribute = {'col0': '2', 'col1': '6', 'col2': '9', 'col3': '4', 'col4': '7', 'col5': '1', 'col6': '1', 'col7': '8', 'col8': '0', 'col9': '1'}
    Delta =  ['col3', 'col2', 'col0', 'col1']
    Weights = [[2, 3, 1], [0]]
    
    #test_time = 100

    kpabe = TFL19(groupObj)
    (msk, pk) = kpabe.setup()
    #m = group.random(GT)
    start = time.time()
    CT = kpabe.encrypt(pk, Attribute)
    end = time.time()
    print("Encryption: ", (end - start)*1000)
    SK = kpabe.keygen(msk, pk, Policy, Policy_Matrix)
    msg = kpabe.decrypt(pk, "lixo", SK, CT, Delta, Weights)
    print("Decryption: ", (end - start)*1000)
    print(msg)


if __name__ == '__main__':
    debug = True
    main()
