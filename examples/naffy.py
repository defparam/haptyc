from haptyc import *

# A response to https://twitter.com/nnwakelam/status/1371608496127373315
# And a better implenmentation than https://twitter.com/defparam/status/1371847176377266194

# Clusterbomb search pattern for admin endpoint
# 
# Example annotated request:
#
# [%method][%end] [%path][%end] HTTP/1.1
#
# Expected Output:
#
# GET /admin/ HTTP/1.1
# POST /admin/ HTTP/1.1
# PUT /admin/ HTTP/1.1
# PATCH /admin/ HTTP/1.1
# GET /admin/../admin HTTP/1.1
# POST /admin/../admin HTTP/1.1
# PUT /admin/../admin HTTP/1.1
# PATCH /admin/../admin HTTP/1.1
#
# etc...
	
class TestLogic(Transform):
    @ApplyList(["GET", "POST", "PUT", "PATCH"])
    def test_method(self, data, state):
        return data
        
    @ApplyPayloads("Admins")
    def test_path(self, data, state):
        return data

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, requestsPerConnection=1, pipeline=0)

    TestFactory = TestLogic(target.req)
    for test in TestFactory:
        engine.queue(test)

def handleResponse(req, interesting):
    table.add(req)