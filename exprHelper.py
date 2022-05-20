class exprTree:
    def __init__(self, dta, r, l):
        self.data = dta
        self.right = r
        self.left = l
        self.v = []
        self.attrIndex = -1
        self.value = 0
    
    def isOperation(self, op):
        return op == "and" or op == "or"

def sepWithDelimiter(lst, delimiter, sp = " "):
    sep = lst.split(sep= sp+delimiter+sp)
    lst2 = [item for i in range(len(sep)-1) for item in [sep[i], delimiter] if item != ""]
    if sep[-1] != "":
        lst2 += [sep[-1]]
    return lst2

def stringToList(strIn):
    separatedLst = [it for sepAnd in sepWithDelimiter(strIn, "and") for it in sepWithDelimiter(sepAnd, "or")]
    addParenteses = [it for sep in separatedLst for it in sepWithDelimiter(sep, "(", sp = "")]
    addParenteses2 = [it for sep in addParenteses for it in sepWithDelimiter(sep, ")", sp = "")]   
    keyS = [{"keyword" : it.split("=")[0].replace(" ",""), "value" : it.split("=")[-1].replace(" ","")} for it in addParenteses2]
    return keyS

def padWithZeros(v, c):
    newV = v.copy()
    while(len(newV) < c):
        newV.append(0)
    return newV

def addV(node, v):
    if node is not None:
       node.v = v.copy()
       return [node]
    return []

def evalT(tree):
    if tree.data == "and":
        return evalT(tree.left) and evalT(tree.right)
    elif tree.data == "or":
        return evalT(tree.left) or evalT(tree.right)
    else:
        return tree.data

def bfsInTree(tree):
    if tree is None:
        return
    c = 1
    tree.v = [1]
    #bfs on tree, preform the first step of the algorithm
    nodeQueue = [tree]
    while(len(nodeQueue) > 0):
        currentNode = nodeQueue.pop(0)
        if currentNode.data == "or":
            nodeQueue += addV(currentNode.left, currentNode.v)
            nodeQueue += addV(currentNode.right, currentNode.v)
        elif currentNode.data == "and":
            v = padWithZeros(currentNode.v, c)
            c += 1
            nodeQueue += addV(currentNode.left, v + [1])
            nodeQueue += addV(currentNode.right, [0 for i in range(c-1)] + [-1])

    #second pass on the tree, equalize vector size
    matrixDict = []
    pol = []
    attrIndex = 0
    nodeQueue = [tree]
    while(len(nodeQueue) > 0):
        currentNode = nodeQueue.pop(0)
        if currentNode.data != "and" and currentNode.data != "or":
            v = padWithZeros(currentNode.v, c)
            currentNode.v = v
            matrixDict.append({currentNode.data : v})
            pol.append({currentNode.data : currentNode.value})
            currentNode.attrIndex = attrIndex
            attrIndex += 1
        if currentNode.left is not None:
            nodeQueue.append(currentNode.left)
        if currentNode.right is not None:
            nodeQueue.append(currentNode.right)

    return matrixDict, pol

def printTree(tree, appendix):
    print(appendix, end = "")
    print(tree.data, tree.v)
    if tree.left is not None:
        print(appendix + "left")
        printTree(tree.left, appendix + "  ") 
    if tree.right is not None:
        print(appendix + "right")
        printTree(tree.right, appendix + "  ") 
    
def getLeastPercedence(expr):
    parCount = 0
    best = {"priority": 1000, "index": -1}
    priority= {"and":1, "or":0}
    for i in range(len(expr)):
        if expr[-i]['keyword'] == ")":
            parCount += 1
        elif expr[-i]['keyword'] == "(":
            parCount -= 1
        elif expr[-i]['keyword'] == "or" or expr[-i]['keyword'] == "and":
            if best["priority"] > parCount * 2 + priority[expr[-i]['keyword']]:
                best = {"priority": parCount * 2 + priority[expr[-i]['keyword']], "index": len(expr) - i}
    #ignoring parentheses
    if best["index"] == -1:
        for i in range(len(expr)):
            if expr[i]['keyword'] != "(" and expr[i]['keyword'] != ")":
                best["index"] = i
    return best["index"]

def exprToTree(tree, exprArray):
    if len(exprArray) == 0:
        return None

    breakIndex = getLeastPercedence(exprArray)
    if breakIndex == -1:
        return None

    tree.data = exprArray[breakIndex]["keyword"]
    tree.value = exprArray[breakIndex]["value"]
    tree.left = exprToTree(exprTree(None, None, None), exprArray[:breakIndex])
    tree.right = exprToTree(exprTree(None, None, None), exprArray[breakIndex+1:])
    return tree


#finds right combination of wheights
def findWheights(tree, w):
    if tree is None:
        return [] 
    #is leaf
    if tree.data != "and" and tree.data != "or":
        w_a = [i + [tree.attrIndex] for i in w] #adds dependency in all lists of dependencies
        return w_a
    #append ands
    elif tree.data == "and":
        w = findWheights(tree.left, w) #updates w
        w = findWheights(tree.right, w)
    #create new lists for or
    elif tree.data == "or":
        wLeft = findWheights(tree.left, w)
        wRight = findWheights(tree.right, w)      
        w = wLeft + wRight
    return w

def parseExpression(strExpr):
    keyS = stringToList(strExpr)
    tree = exprToTree(exprTree(None, None, None), keyS)
    policyMatrix, policy = bfsInTree(tree)
    deltas = findWheights(tree, [[]])
   
    return policyMatrix, policy, deltas

#print(parseExpression("ID = 9 and (Info = 4 or Sergio = 3) and Serginho = 5"))


def strToPythonExpr(strIn, lstName="lst"):
    separatedLst = [it for sepAnd in sepWithDelimiter(strIn, "and") for it in sepWithDelimiter(sepAnd, "or")]
    addParenteses = [it for sep in separatedLst for it in sepWithDelimiter(sep, "(", sp = "")]
    addParenteses2 = [it for sep in addParenteses for it in sepWithDelimiter(sep, ")", sp = "")]
    
    sepEquals = [it for sepLst in addParenteses2 for it in sepWithDelimiter(sepLst, "=", sp="")]
    indices = [i for i, x in enumerate(sepEquals) if x == "="] #indices with '='
    for i in indices:
        sepEquals[i-1] = ("x[\'" + sepEquals[i-1] + "\']").replace(" ", "")
        sepEquals[i] = "=="
        sepEquals[i+1] = "str(" + sepEquals[i+1] + ")"
    return " ".join(sepEquals)
    #return "["+(" ".join(sepEquals)) + " for x in " + lstName + "]"