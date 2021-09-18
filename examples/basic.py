from haptyc import *

# Simple Basic Transform
#
# Example Annotated Request:
#
# GET /animals/[+h1]deer[+end] HTTP/1.1
#
# Issued Tests:
#
# GET /animals/Moose HTTP/1.1
# GET /animals/Moose HTTP/1.1
# GET /animals/Moose HTTP/1.1
# GET /animals/Moose HTTP/1.1
# GET /animals/Moose HTTP/1.1
#

class TestLogic(Transform):
    @ApplyIteration(5)
    def test_h1(self, data, state):
        return "Moose"

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, requestsPerConnection=1, pipeline=0)

    TestFactory = TestLogic(target.req)
    for test in TestFactory:
        engine.queue(test)

def handleResponse(req, interesting):
    table.add(req)