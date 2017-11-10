import argparse
import csv
import glob
import math
import pandas as pd
import time
from collections import Counter
from collections import defaultdict
from scipy import stats
from tqdm import tqdm
import itertools
import warnings



from subprocess import Popen, PIPE, STDOUT

def stringMagic(s):


    if not s:
        # print("strMagic not S ERROR: " + str(s))

        return([0,0,0, 0])


    countTotal = len(s)
    ss = tuple(tuple(x) for x in s)
    countUnique = len(set(ss))
    percentageUnique = countUnique/countTotal
    
   
    #print(s)
    #mode = stats.mode(s)[0][0] 

    modeCount = stats.mode(s)[1][0]
    if str(type(modeCount)) == "<class 'numpy.ndarray'>":
        modeCount = modeCount[0]
    percentageMode = modeCount/countTotal


    #print("strMagic ERROR: " + str(s))
    #modeCount = stats.mode([s])[1][0]
    #modeCount = 0
    #percentageMode = 0

    return([countUnique, percentageUnique, modeCount, percentageMode])


    
def mathMagic(k):
    if k:
        countTotal = len(k)
        countUnique = len(set(k))
        percentageUnique = countUnique/countTotal
        average = float(sum(k) / float(len(k)))  # Average
        minimum = min(k)  # min
        maximum = max(k)  # max
        entStat = stats.entropy(k)  # entropy
        if math.isnan(entStat):  # if is not a number
            entStat = 0  # set = 0
        varStat = stats.variation(k)  # variation
        if math.isnan(varStat):  # if is not a number
            varStat = 0  # set = 0
        skewStat = stats.skew(k)  # skew
        kurtStat = stats.kurtosis(k)  # kurtosis  
    
    else:

        return([0]*9) # Why does this fuck up for time so bad?
    

    return([countUnique, percentageUnique, average, minimum, maximum, entStat, varStat, skewStat,kurtStat])

def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        return False
        

def is_good(row, length):

    if len(row) != length:
        return False
    #elif len(row[0]) != 17:
    #    return False
    else:
        s = str('.'.join(row[8].split(".")[-2:]))
    
        if "#" in s or "/" in s or "=" in s or "/" in s:
            return False
        else:
            return True
        


def dictionaryToArrays(magicDictionary):

    supahArray = []
    badArray = []
    #print("Converting Dictionary to Arrays")
    for i in magicDictionary:


        outted = enrichHTTP(magicDictionary[i],i)
        if outted == False:
            break
        else:
            supahArray.append(outted)
            
    

    flatList = [item for sublist in supahArray for item in sublist]
    return(flatList)
            
def domainEnrich(domainNameFull):

    
    domainName = '.'.join(domainNameFull.split(".")[-2:]).lower()
    
    try:
        tld = domainName.split(".")[1]
    except:
        tld = domainName

    domainEntropy = entropy(domainName)
    return [ domainName, tld, domainEntropy]

def subdomainEnrich(subdomainName):

    if subdomainName == []:
            subdomainName = ["-"]
            subdomainDepth = 0
            subdomainLength = 0
            subdomainEntropy = 0    
    if subdomainName[0] == "www":
        del subdomainName[0]
        
    if subdomainName == []:
            subdomainName = ["-"]
            subdomainDepth = 0
            subdomainLength = 0
            subdomainEntropy = 0
            
    subdomainNameJoined = (''.join(subdomainName)).lower()
    subdomainNameP = ('.'.join(subdomainName)).lower()
    
    subdomainDepth = len(subdomainName)
    subdomainLength = len(subdomainNameJoined)
    subdomainEntropy = entropy(subdomainNameJoined)

    return [subdomainNameP, subdomainDepth, subdomainLength, subdomainEntropy]

def entropy(s):
    p, lns = Counter(s), float(len(s))
    return -sum(count / lns * math.log(count / lns, 2) for count in p.values())
    
def timeEnrich(time):
    time = float(time)
    return(time)
    

def connLogEnrich(uid): 
    pathToConnLog = '2017-cdx-logs/bro_conn_log'
    cmd = "grep " + uid + " " + pathToConnLog
    #print(uid)

    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    #output = p.stdout.readlines()
    temp = str(p.stdout.readlines())

    a = temp.strip().split('\\t') 

    if not is_good(a, 21):
        return(False)
        




        
    return(a)
"""    
def connLogEnrich(uid):
    pathToConnLog = '2017-cdx-logs/bro_conn_log'
    cmd = "grep " + uid + " " + pathToConnLog
    #print(uid)
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    #output = p.stdout.readlines()
    try:
        temp = (str(p.stdout.readlines()[0]).strip().split('\\t') )
        
        return(temp)
    except:
        print(str(p.stdout.readlines()))
        return(False)
"""
        
    

        
def uriEnrich(domainName, uri):
  
    #filetype?
    # php?
    # symbol

    #x one hot
    #x length
    #x depth
    #x entropy
    # last chars
    # filetype 
    # percentage of alphanum
    # distance between the things
    httpsFlag = 0   
    if domainName in uri:
        w = uri.split(domainName)[1]
        if w == ":443":
            httpsFlag = 1

        lengthTemp = len(w)
        x = w.split("/")
        depthTemp = len(x)-1
        entropyTemp = entropy(''.join(x))
        
    else:

        w = uri
        lengthTemp = len(w)
        x = w.split("/")
        depthTemp = len(x)-1
        entropyTemp = entropy(''.join(x))
        
    return(w, lengthTemp, depthTemp, entropyTemp, httpsFlag)
        
    
def agentEnrich(agent):
    w = agent
    lengthTemp = len(w)
    x = w.split(" ")
    depthTemp = len(x)-1
    entropyTemp = entropy(''.join(x))
        
    return(lengthTemp, depthTemp, entropyTemp)
    
def insideEnrichHTTP(j,domainName,timeArray,connArray,arbysArray,uriArray,agentArray):

    
    
    connLogList = connLogEnrich(j[1]) 

    if not connLogList: 
        arbysArray[4].append(1) # this measures http requests with no connections
        return(timeArray, connArray, arbysArray, uriArray, agentArray)
    #connLogList = connLogEnrichDomain(domainName)
    

    connArray[0].append([connLogList[6]]) # string/option # proto
    connArray[1].append([connLogList[7]]) # string/option # service

    connArray[2].append(float(connLogList[8])) # num #duration
    connArray[3].append(int(connLogList[9])) # num 
    connArray[4].append(int(connLogList[10])) # num
    connArray[5].append(int(connLogList[16])) # num
    connArray[6].append(int(connLogList[17])) # num
    connArray[7].append(int(connLogList[18])) # num
    connArray[8].append(int(connLogList[19])) # num

    #except: 
    #    return(timeArray, connArray, arbysArray, uriArray, agentArray)
    ####### [0] 
    
    timeArray.append(float(j[0]))

    ###### [6] trans_depth: Represents the pipelined depth into the connection of this request/response transaction.
    arbysArray[0].append(int(j[6])) 
    
    ###### [7] method: Verb used in the HTTP request (GET, POST, HEAD, etc.).
    arbysArray[1].append([j[7]]) 
    
    ##### [8] host header
    # Subdomain
    subdomainName = (j[8].split(".")[:-2])
    
    subdomainName, subdomainDepth, subdomainLength, subdomainEntropy = subdomainEnrich(subdomainName)  

    if subdomainName != "-":
        arbysArray[2].append(subdomainName) 
    
    #subdomainName
    """subdomainEntropyAvgList.append(subdomainEntropy)
    subdomainLengthAvgList.append(subdomainLength)
    subdomainDepthAvgList.append(subdomainDepth)  """
    
    # Domain
    #hostDomainArray.append(j[8])
    
    ###### [9] uri: URI used in the request
    ### Decompose URI into as many features as possible
    uriEnriched = uriEnrich(j[8], j[9])
    
    if uriEnriched[4] == False:
        uriArray[0].append([uriEnriched[0]])  #name
        uriArray[1].append(uriEnriched[1]) #len
        uriArray[2].append(uriEnriched[2]) # dep
        uriArray[3].append(uriEnriched[3]) #ent
        
    uriArray[4].append(uriEnriched[4]) #is it https # bool
       
   
    ###### [10] referer
    # Domain
    #referrerDomainList.append(j[10])
    
    ##### [12] UserAgent
    ### Decompose the user agent into a ton of features
    agentEnriched = agentEnrich(j[11])
    
    agentArray[0].append([j[11]])
    agentArray[1].append(agentEnriched[0])
    agentArray[2].append(agentEnriched[1])
    agentArray[3].append(agentEnriched[2])
    return(timeArray, connArray, arbysArray, uriArray, agentArray)
    
def enrichHTTP(dictEntry, domainName):

    subdomainArray = []
    subdomainBigramAvgList = []
    subdomainEntropyAvgList = []
    subdomainLengthAvgList = []
    subdomainDepthAvgList = []
    timeList = []

    connLogList = []
    timeArray = []
    protoArray = []
    serviceArray = []
    durationArray = []
    origBytesArray = []
    respBytesArray = []
    origPacketsArray = []
    origIpBytesArray = []
    respPacketsArray = []
    respIpBytesArray = []
    
    transList = []
    methodList = []
    
    uriList = []
    ### 
    uriLenList = []
    uriDepList = []
    uriEntList = []
    uriHttpsList = []
    ####
    agentList = []
    agentLenList = []
    agentDepList = []
    agentEntList = []
    
    connArray = [[],[],[],[],[],[],[],[],[],[],[]]
    timeArray = []
    arbysArray = [[],[],[],[],[]]
    uriArray = [[],[],[],[],[],[]]
    agentArray = [[],[],[],[],[]]
    
    requestLenList = []
    responseLenList = []
    
    
    tempArray = []
    finalArray = []
    flatArray = []
    
    if domainName == "-":
            #print("ERROR")
            #print(dictEntry)
            # Fail softly, you loser.
            domainName = "fucked.com"
            

    # Domain Name
    domainName, tld, domainEntropy = domainEnrich(domainName)
    
    
    print("Enriching " + str(domainName))
    for j in dictEntry:
        timeArray, connArray, arbysArray, uriArray, agentArray = insideEnrichHTTP(j, domainName, timeArray, connArray, arbysArray, uriArray, agentArray)
        #insideEnrichHTTP(j, domainName, timeArray, connArray, arbysArray, uriArray, agentArray)
        
    #### Aggregation Features ####
    # Time   



    deltaTimeList = [j - i for i, j in zip(timeArray[:-1], timeArray[1:])]
    #print(connArray[2])
    
    count = len(connArray[2])

    magicDurationArray = mathMagic(connArray[2])
    magicOrigBytesArray = mathMagic(connArray[3])
    magicRespBytesArray = mathMagic(connArray[4])
    magicOrigPacketsArray = mathMagic(connArray[5])
    magicOrigIpBytesArray = mathMagic(connArray[6])
    magicRespPacketsArray = mathMagic(connArray[7])
    magicRespIpBytesArray = mathMagic(connArray[8])

    
    #### Convert To Features ####
    
    # Bool Math
   

    

    # String Math
    temp0 = stringMagic(arbysArray[2]) # this is broken.
    temp1 = stringMagic(agentArray[0])
    temp2 = stringMagic(uriArray[0])
    #temp3 = stringMagic(methodList)
    
    # Math Math
    temp_0 = mathMagic(deltaTimeList)

    temp_2 = mathMagic(uriArray[1])
    temp_3 = mathMagic(uriArray[2]) 
    temp_4 = mathMagic(uriArray[3]) 
    temp_5 = mathMagic(agentArray[1])
    temp_6 = mathMagic(agentArray[2]) 
    temp_7 = mathMagic(agentArray[3]) 
    
    tempArray.extend((
        temp0,
        temp1,
        temp2,
        temp_0,
        magicDurationArray,
        magicOrigBytesArray,
        magicRespBytesArray,
        magicOrigPacketsArray,
        magicOrigIpBytesArray,
        magicRespPacketsArray,
        magicRespIpBytesArray,
        temp_2,
        temp_3,
        temp_4,
        temp_5, 
        temp_6,
        temp_7,     
        
    ))

    tempArray = list(itertools.chain.from_iterable(tempArray))
    
    finalArray.extend((
        [domainName],
        [count],
        tempArray,
        ))
        
    finalArray = list(itertools.chain.from_iterable(finalArray))

    return(finalArray)
    
def listMaker(csvOne):

    f = open(csvOne)
    csv_f = csv.reader(f)


    listOfNames = []

    for row in csv_f:
        try:
      
            if is_good(row, 12):
                dictKey = str('.'.join(row[8].split(".")[-2:]))
                
                if is_number(dictKey[-1]):
                    b = "0"
                else:
                    if dictKey in listOfNames:
                        b = "0"
               
                    else:
            
                        listOfNames.append(dictKey)
                   
              
        except:
            print("ERROR: " + str(row))
        
        
        

    return(listOfNames)
        
        

def dictionaryMaker(csvOne, targetDomain):
    
    magicDictionary = defaultdict(dict)
    f = open(csvOne)
    csv_f = csv.reader(f)


    
    print("Making Dictionary " + targetDomain)
    for row in csv_f:

        try:
            length = 30
            if is_good(row, 12):
                dictKey = str('.'.join(row[8].split(".")[-2:]))

                
                if is_number(dictKey[-1]):
                    x = 0
                if dictKey != targetDomain:
                    x = 0
                else:
                    if dictKey in magicDictionary:
                        magicDictionary[dictKey].append(row)
                        
               
                    else:
            
                        magicDictionary[dictKey] = [row]
                   
              
        except:
            print("ERROR: " + str(row))
        
        
        
    
    return(magicDictionary)
    
def threadedFunction(i):
    magicDictionary = dictionaryMaker("myOut.csv", i)    

    temp = dictionaryToArrays(magicDictionary)
    with open("to.csv", "at") as f:
        writer = csv.writer(f)
        writer.writerow(temp)
        


    
blacklist = ["usma.bluenet", "usna.bluenet", "hq.bluenet", "range.bluenet", "rmc.bluenet"]

listOfNames = listMaker("myOut.csv")
#listOfNames = ["osha.gov"]
for name in blacklist:
    listOfNames.remove(name)
    
    
from multiprocessing.dummy import Pool as ThreadPool 
pool = ThreadPool(1) 
finalArray = pool.map(threadedFunction, listOfNames)
    

