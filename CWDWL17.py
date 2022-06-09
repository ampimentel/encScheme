'''
Hui Cui, Zhigou Wan, Robert H. Deng, Guilin Wang, Yingjiu Li
 
| From: "Efficient and Expressive Keyword Search over Encrypted Data in the Clouds"
| Published in: 
| Available from: 
| Notes: Security Assumption:

* type:           SE supporting monotonic search query
* setting:        Pairing

:Authors:    Yi-Fan Tseng
:Date:            08/30/2019
'''
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.hash_module import Hash
import time

debug = False
class CWDWL17(ABEnc):
    
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, debug)        
        group = groupObj

    def setup(self):
        g, g_hat = group.random(G1), group.random(G2)
        x1, x2, x3 = group.random(), group.random(), group.random() #Zp
        u = g ** x1
        u_hat = g_hat ** x1
        h = g ** x2
        h_hat = g_hat ** x2
        w = g ** x3
        w_hat = g_hat ** x3
        #u, h, w= group.random(G1), group.random(G1), group.random(G1)
        #u_hat, h_hat, w_hat = group.random(G2), group.random(G2), group.random(G2)
        alpha, d1, d2, d3, d4 = group.random(), group.random(), group.random(), group.random(), group.random()
        g1 = g**d1
        g2 = g**d2
        g3 = g**d3
        g4 = g**d4
        pk = {"g":g, "u":u, "h":h, "w":w, "g1":g1, "g2":g2, "g3":g3, "g4":g4, "Omega":pair(g, g_hat)**alpha}
        msk = pk.copy()
        msk["alpha"] = alpha
        msk["g_hat"] = g_hat
        msk["u_hat"] = u_hat
        msk["h_hat"] = h_hat
        msk["w_hat"] = w_hat
        msk["d1"] = d1
        msk["d2"] = d2
        msk["d3"] = d3
        msk["d4"] = d4

        return (msk, pk)

    def s_keygen(self, pk):
        gamma = group.random()
        (pk_s, sk_s) = (pk["g"]**gamma, gamma)
        return (pk_s, sk_s)

    def encrypt(self, pk, Keyword):
        H = Hash(group)
        mu = group.random()

        CT = dict()
        C = pk["Omega"]**mu
        D = pk["g"]**mu
        CT["C"] = C
        CT["D"] = D

        for name, value in Keyword.items():
            z, s1, s2 = group.random(), group.random(), group.random()
            htemp = H.hashToZr(name + value)

            D = (pk["w"] ** -mu) * ( ((pk["u"] ** htemp) * pk["h"]) ** z )
            E1 = pk["g1"] ** (z - s1)
            E2 = pk["g2"] ** s1
            F1 = pk["g3"] ** (z - s2)
            F2 = pk["g4"] ** s2
            CT[name] = {"D":D, "E1":E1, "E2":E2, "F1":F1, "F2":F2}
        CT["mu"] = mu
        return CT
    
    #assumptions: Pol and Pol_M are a list of dicts with the same number of entries and matching keyword names
    def keygen(self, msk, pk_s, Pol, Pol_M, wheights = [[]]):
        H = Hash(group)
        SK = dict()
        s, y2, y3 = msk["alpha"], group.random(), group.random()
        yVector = [s] + [group.random() for i in range(len(Pol)-1)]
        r, r_prime = group.random(), group.random()
        d1 = msk["d1"]
        d2 = msk["d2"]
        d3 = msk["d3"]
        d4 = msk["d4"]

        T = msk["g"] ** r
        T_hat = msk["g_hat"] ** r_prime
        SK["T"] = T
        SK["T_hat"] = T_hat

        X = pair(pk_s, T_hat) ** r
        X = H.hashToZr(X)

        SK['attr'] = []

        for dictEntryM, dictEntryP in zip(Pol_M, Pol):
            name, row = next(iter(dictEntryM.items())) #get entry form dict => key:row
            lamb = 0
            for r, y in zip(row, yVector):
                lamb += r*y
            t1, t2 = group.random(), group.random()

            t = d1*d2*t1 + d3*d4*t2
            h = H.hashToZr(name + dictEntryP[name])
            Y = (msk["u_hat"]**h) * msk["h_hat"]

            T1 = ( msk["g_hat"] ** lamb ) * ( msk["w_hat"] **  t)
            T2 = msk["g_hat"]** (t+X) # ERRADO?? =>  msk["g_hat"]** t * x
            #T2 = msk["g_hat"]** t
            T3 = Y ** (-d2*t1)
            T4 = Y ** (-d1*t1)
            T5 = Y ** (-d4*t2)
            T6 = Y ** (-d3*t2)

            SK["attr"].append({"T1":T1, "T2":T2, "T3":T3, "T4":T4, "T5":T5, "T6":T6})
            SK["g_hat"] = msk["g_hat"] #FORA DO LOOP?
            

        return SK

    def decrypt(self, pk, sk_s, SK, CT, Delta, weights = [[]]):
        H = Hash(group)
        Y = 1
        X = pair(SK["T"], SK["T_hat"]) ** sk_s
        X = H.hashToZr(X)
        X = SK["g_hat"] ** X

        attrQuery = []
        #compute Y for all atributes
        for name, sk_attr in zip(Delta, SK["attr"]):
            Y = 1
            Y *= pair(CT["D"], sk_attr["T1"])
            T2 = sk_attr["T2"] / X
            #T2 = SK[name]["T2"] 
            Y *= pair(CT[name]["D"], T2)
            Y *= pair(CT[name]["E1"], sk_attr["T3"])
            Y *= pair(CT[name]["E2"], sk_attr["T4"])
            Y *= pair(CT[name]["F1"], sk_attr["T5"])
            Y *= pair(CT[name]["F2"], sk_attr["T6"])
            attrQuery.append(Y)
        
        for query in weights:
            evalQuery = 1
            for wi in query:
                evalQuery*=attrQuery[wi]
            if CT["C"] == evalQuery:
                return True
        return False
        

def main():
    #Get the eliptic curve with the bilinear mapping feature needed.
    #groupObj = PairingGroup('MNT224')
    groupObj = PairingGroup('BN254')
    #Policy_Matrix = [{'School':[1, 1, 0]}, {"Pos":[0, -1, 0]}]
    #Policy = [{'School':"NSYSU"}, {"Pos":"Teacher"}]
    #Keyword = {"School":"NSYSU", "Pos":"Teacher"}
    #Delta = ["School", "Pos"]
    #Weights = [[0, 1]]
    Policy_Matrix = [{'col3': [1, 0, 0]}, {'col2': [0, -1, 0]}, {'col0': [1, 1, 1]}, {'col1': [0, 0, -1]}] 
    Policy = [{'col3': '4'}, {'col2': '10'}, {'col0': '8'}, {'col1': '9'}]
    Keyword = {'col0': '2', 'col1': '6', 'col2': '9', 'col3': '4', 'col4': '7', 'col5': '1', 'col6': '1', 'col7': '8', 'col8': '0', 'col9': '1'}
    Delta =  ['col3', 'col2', 'col0', 'col1']
    Weights = [[2, 3, 1], [0]]
    
    kpabks = CWDWL17(groupObj)

    (msk, pk) = kpabks.setup()
    (pk_s, sk_s) = kpabks.s_keygen(pk)
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
