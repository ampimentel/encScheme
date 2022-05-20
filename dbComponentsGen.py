import random


def dbGenerator(parameters):
    #random.seed(seed)
    db = []
    for i in range(parameters["numLines"]):
        entry = {parameters["colName"] + str(j) : str(random.randint(0, parameters["attrSpread"])) for j in range(parameters["numCols"])}        
        db.append(entry)
    return db

genQuery = lambda colName, maxAttr : colName + " = " + str(random.randint(0, maxAttr))

def generateFlatQuery(inputs, size, over = 0):
    query = genQuery(inputs["colName"] + str(over),  inputs["attrSpread"])
    for i in range(1, size):
        if i + over >= inputs["numCols"]:
            break
        operator = "and"
        if random.randint(0, 1) == 1:
            operator = "or"
        query += " " + operator + " " + genQuery(inputs["colName"] + str(over + i),  inputs["attrSpread"])
    return query

def generateCompositeQuery(inputs, size, over = 0):
    end = " "
    query = " "
    for i in range(0, size-1):
        if i + over >= inputs["numCols"] - 1:
            break
        operator = "and"
        if random.randint(0, 1) == 1:
            operator = "or"
        query += genQuery(inputs["colName"] + str(over + i),  inputs["attrSpread"]) + " " + operator + " ("
        end += ")"
    query += genQuery(inputs["colName"] + str(over+size-1),  inputs["attrSpread"]) + end
    return query

def randFunc(inputs, size, over = 0):
    if random.randint(0, 1) == 0:
        return generateCompositeQuery(inputs, size, over)
    return generateFlatQuery(inputs, size, over)

def queryGenerator(inputs, size):
    accum = 0
    operator = ""
    query = ""
    while(accum < size):
        r = random.randint(1, size)
        if r + accum > size:
            r = size - accum
        if accum > 0:
            operator = " and "
            if random.randint(0, 1) == 1:
                operator = " or "
        query += operator + randFunc(inputs, r, accum)
        accum += r
    return query

def generateQueries(inputs, numQueries, maxSize):
    if maxSize > inputs["numCols"]:
        maxSize = inputs["numCols"]
    return [queryGenerator(inputs, random.randint(1, maxSize)) for i in range(numQueries)] 
