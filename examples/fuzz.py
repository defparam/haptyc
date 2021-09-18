from haptyc import *
from base64 import b64encode, b64decode
import json
	
class TestLogic(Transform):
    #
    # test_h1: Decodes base64, fuzzes using random_insert, Re-encodes base64
    # Number of tests: 50
    #
    @ApplyIteration(50)
    def test_h1(self, data, state):
        data = b64decode(data)
        data = random_insert(data,list("'"))
        data = b64encode(data)
        return data
    #
    # test_jsonfuzz: Deserialize JSON
    #                Loop through every key
    #                Decodes base64
    #                fuzzes using random_insert
    #                Re-encodes base64
    #                Serialize JSON
    # Number of tests: 50
    #        
    @ApplyIteration(50)
    def test_jsonfuzz(self, data, state):
        JA = json.loads(data)
        for key in JA:
            JA[key] = b64encode(random_insert(b64decode(JA[key]), list("!@#$%^&*()")))
        return json.dumps(JA)

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, requestsPerConnection=1, pipeline=0)

    TestFactory = TestLogic(target.req)
    for test in TestFactory:
        engine.queue(test)

def handleResponse(req, interesting):
    table.add(req)
