from CWDWL17 import CWDWL17
from exprHelper import parseExpression, strToPythonExpr
from charm.toolbox.pairinggroup import PairingGroup
from charm.core.engine.util import objectToBytes,bytesToObject
from dbComponentsGen import dbGenerator, generateQueries

import csv
import time
import pickle
import argparse
import random
from math import ceil
groupObj = PairingGroup('BN254')
kpabks = CWDWL17(groupObj)

def end_bench(group, operation, n):
    group.EndBenchmark()
    benchmarks = group.GetGeneralBenchmarks()
    cpu_time = benchmarks['CpuTime']
    real_time = benchmarks['RealTime']
    return "%s,%d,%f,%f" % (operation, n, cpu_time, real_time)

def end_bench_dict(group, ctx, component = None):
    group.EndBenchmark()
    benchmarks = group.GetGeneralBenchmarks()
    cpu_time = benchmarks['CpuTime']
    real_time = benchmarks['RealTime']
    info = {**ctx, "cpu time" : cpu_time, "real time" : real_time}
    if component is not None:
        info["size"] = len(objectToBytes(component, groupObj))
    return info

def start_bench(group):
    group.InitBenchmark()
    group.StartBenchmark(["RealTime", "CpuTime"])


def encryptDB(db, pk):
    return [kpabks.encrypt(pk, dict(entry)) for entry in db]

def encryptDBFromFile(filePlainText, pk):
    with open(filePlainText, mode="r") as file:
        csv_reader = csv.DictReader(file, delimiter=';')
        start_bench(groupObj)
        encDb = [kpabks.encrypt(pk, dict(entry)) for entry in csv_reader]
        print(end_bench(groupObj, "Encrypt Db", 100))
    return encDb

def genTrap(strIn, pk_s, msk):
    #start_bench(groupObj)
    policyMatrix, policy, deltas = parseExpression(strIn)
    SK = kpabks.keygen(msk, pk_s, policy, policyMatrix)
    #print(end_bench(groupObj, "Generate Trapdoor", 1))
    return {"key" : SK, "lssWeights" : deltas, "delta": [next(iter(en.keys())) for en in policy]}

def searchOnEncDb(encDb, pk, sk_s, trap):
    return [CT for CT in encDb if kpabks.decrypt(pk, sk_s, trap["key"], CT, trap["delta"], trap["lssWeights"])]

def compareResults(encDb, pk, sk_s, trap, dB, query, storeRes = None):
    encResults = [kpabks.decrypt(pk, sk_s, trap["key"], CT, trap["delta"], trap["lssWeights"]) for CT in encDb]
    res = {}
    if storeRes is not None:
        res = end_bench_dict(groupObj, storeRes)
    res["result"] = True
    
    strExpr = strToPythonExpr(query, lstName="dB")
    #normalResults = eval(strExpr)
    normalResults = [eval(strExpr) for x in dB]
    #print("*Search:", time.time() - init)
    for enc, plain, i in zip (encResults, normalResults, range(len(normalResults))):
        #print(enc, "vs", plain)
        if enc != plain:
            print("ERRROR: ", dB[i], plain, i)
            res["result"] = False
            return res
    return res

#write bytes to file
def writeToFile(encDB, msk, pk, pk_s, sk_s, filename):
    obj1 = [objectToBytes(en, groupObj) for en in [msk, pk, pk_s, sk_s]]
    objList = obj1 + [objectToBytes(en, groupObj) for en in encDB]
    with open(filename, mode="wb") as file:
        pickle.dump(objList, file)
    
def readFromFile(filename):
    with open(filename, mode="rb") as file:
        objList = pickle.load(file)
    msk = bytesToObject(objList[0], groupObj)
    pk = bytesToObject(objList[1], groupObj)
    pk_s = bytesToObject(objList[2], groupObj)
    sk_s = bytesToObject(objList[3], groupObj)
    return msk, pk, pk_s, sk_s, [bytesToObject(en, groupObj) for en in objList[4:]]

def readOriginalFromFile(filename):
    with open(filename, mode="r") as file:
        csv_reader = csv.DictReader(file, delimiter=';')
        dB = [dict(entry) for entry in csv_reader]
    return dB 

def complex_test():
    parser = argparse.ArgumentParser()
    parser.add_argument('--plainDB', required = True, help='Plaintext DB file')
    parser.add_argument('--encDB', nargs='?', help='Encrypted dB, if we have it already')
    parser.add_argument('--query', help='Query to be performed on the dB')
    args = parser.parse_args()
    print(args)
    dB = readOriginalFromFile(args.plainDB)
    #load db
    if args.encDB is not None:
        msk, pk, pk_s, sk_s, encDb = readFromFile(args.encDB)
    else:
        (msk, pk) = kpabks.setup()
        (pk_s, sk_s) = kpabks.s_keygen(pk)
        encDb = encryptDBFromFile(args.plainDB, pk)
        writeToFile(encDb, msk, pk, pk_s, sk_s, "encDb.ct")
    #encrypt dB
    if args.query is not None:
        trapdoor = genTrap(args.query, pk_s, msk)
        print(compareResults(encDb, pk, sk_s, trapdoor, dB, args.query))
        #expr = "ID = 9 or Info = 3"       
   
def simple_test():
    expr = "ID = 9 and (Info = 3 or Info = 4)"
    entry = {'ID': '9', 'Info': '5', 'Velocity': '32', 'PositionX': '115.909', 'PostionY': '78.229', 'Time': '407528', 'Sensor 1': '0.221555327', 'Sensor 2': '0.70161049', 'Vehicle Path': 'random string'}
    (msk, pk) = kpabks.setup()
    (pk_s, sk_s) = kpabks.s_keygen(pk)
    encDb = [kpabks.encrypt(pk, entry)]
    trap = genTrap(expr, pk_s, msk)
    print("Delta: ", trap["delta"], "lssWeights:", trap["lssWeights"])

    res = [kpabks.decrypt(pk, sk_s, trap["key"], CT, trap["delta"], trap["lssWeights"]) for CT in encDb]
    print(res)

#generate plaintext db
def doMeasures(inputs, times):

    db = dbGenerator(inputs)
    start_bench(groupObj)
    (msk, pk) = kpabks.setup()
    times["setup"].append(end_bench_dict(groupObj, inputs))
    start_bench(groupObj)
    (pk_s, sk_s) = kpabks.s_keygen(pk)
    times["keygen"].append(end_bench_dict(groupObj, inputs))
    start_bench(groupObj)
    encDb = encryptDB(db, pk)
    times["encrypt"].append(end_bench_dict(groupObj, inputs, encDb))

    
    queries = generateQueries(inputs, 10, ceil(inputs["numCols"] / 2))

    for qi in queries:
        start_bench(groupObj)
        trapdoor = genTrap(qi, pk_s, msk)
        times["genTrap"].append(end_bench_dict(groupObj, {**inputs, **{"query" : qi}}, trapdoor))
        start_bench(groupObj)
        res = compareResults(encDb, pk, sk_s, trapdoor, db, qi, {**inputs, **{"query" : qi}})
        times["search"].append(res)

def writeKeysToFiles(times, folder, endFileName=""):
    for key in times.keys():
        with open(folder + "/" + key + endFileName + ".csv", mode="w") as file:
            writer = csv.DictWriter(file, fieldnames = times[key][0].keys())
            writer.writeheader()
            for entry in times[key]:
                writer.writerow(entry)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--seed', required = True, type = int, help='Seed to random generate data')
    parser.add_argument('--pathMeasures', default = "measures", help='Path to Measures Folder')

    args = parser.parse_args()
    print(args.pathMeasures)

    numLines = [1]#, 5, 10, 100, 1000, 100000]#, 10, 50, 100, 1000, 10000]
    numCols = [1, 3]#, 5, 10, 100]
    colName = ["col"]#, "cooooooooooooooooooooooooooooooooooooooooooooooooooooooool"]
    attrSpread = [10, 1000]#, 10, 100]
    times = {"setup" : [], "keygen" : [], "encrypt" : [], "genTrap":[], "search" : []}
    random.seed(args.seed)
    for c in numCols:
        for l in numLines:
            for cN in colName:
                for aS in attrSpread:
                    inputs = {"numCols" : c, "numLines" : l, "colName" : cN, "attrSpread" : aS}
                    print(inputs)
                    doMeasures(inputs, times)

    writeKeysToFiles(times, args.pathMeasures, endFileName = str(args.seed))
main()
#1)crio db
#2)Produzo umas 5 queries para essa db => Round de queries
#3)Rodo todos os rounds de queries
#4)Conto os tempos e guardo em um ficheiro




#considerações:
#não permite aind recuperar os elementos desencriptados
#o servidor sabe parte da query: "ID and Info"
#podem ser usados mecanismos de caching para acelerar as querys: associar trapdoors a entradas da dB
#podemos ainda usar estratégias mistas: guardar apenas alguns valores críticos (timestamp, velocidade, Enc(ID))
