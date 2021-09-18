from haptyc import *
from base64 import b64encode, b64decode
import random, base64

class TestLogic(Transform):
    # Transform that issues 1000 radamsa mutations, can be applied anywhere
    @ApplyIteration(1000)
    def test_radamsa(self, data, state):
        return radamsa(data)
        
    # Transform that bruteforces all uppercase 3 letter combinations
    @ApplyIteration(26*26*26)
    def test_letter3(self, data, state):
        if state.init:
            state.blah = []
            for a in list("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
                for b in list("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
                    for c in list("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
                        state.blah += ["%s%s%s"%(a,b,c)]            
            return
        return state.blah[state.iter]
        
    # Transform that issues 1000 random_insert mutations of various characters, can be applied anywhere
    @ApplyIteration(1000)
    def test_randinsert(self, data, state):
        return random_insert(data, list(".#@$%^&*!'\"><;/\\"))
    
    # Transform that issues 1000 random_insert mutations of characters that exist in the inner data, can be applied anywhere    
    @ApplyIteration(1000)
    def test_selfinsert(self, data, state):
        return random_insert(data, list(set(list(data))))
    
    # Transform that issues 1000 test that parses all cookies, selects a random cookie, performs a random_insert into the
    # cookie data using the character set of that cookie, replaces that specific cookie mutated with rest unchanged.
    # This transform is only meant to wrap the entire "Cookie:" header line
    @ApplyIteration(1000)
    def test_selfinsertcookie(self, data, state):
        data = data.split(';')
        i = random.randint(0,len(data)-1)
        payload = data[i].split('=')
        inner = '='.join(payload[1:])
        inner = random_insert(inner, list(set(list(inner))))
        payload = payload[0] + '=' + inner
        self.set_label(payload)
        data[i] = payload
        return ';'.join(data)

    # Transform that issues 1000 tests that parses all cookies, selects a random cookie, performs a random_insert into the
    # cookie data with 40 A characters, replaces that specific cookie mutated with rest unchanged.
    # This transform is only meant to wrap the entire "Cookie:" header line. The intention is to see AAAAAA characters
    # reflected back at the response
    @ApplyIteration(1000)
    def test_bigcookie(self, data, state):
        data = data.split(';')
        i = random.randint(0,len(data)-1)
        payload = data[i].split('=')
        inner = '='.join(payload[1:])
        inner = random_insert(inner, ["A"*40])
        payload = payload[0] + '=' + inner
        self.set_label(payload)
        data[i] = payload
        return ';'.join(data)
        
    # Transform that issues 100 tests that tries to add random directory back traverses
    # This transform is meant to wrap the endpoint line
    @ApplyIteration(100)
    def test_urlslashattack(self, data, state):
        data = data.split("/")
        i = random.randint(1,len(data)-1)
        data[i] = data[i] + "/../" + data[i]
        return '/'.join(data)
    
    # Standard Dirsearch endpoint search, his transform is meant to wrap the endpoint line
    @ApplyPayloads("dirsearch")
    def test_dirsearch(self, data, state):
        return data.replace(".%EXT%","")
        
    # Transform that issues 1000 tests that decodes a JWT and attempts to mutate the middle payload using random_insert
    # and re-encodes the JWT. Intended to wrap JWTs and is looking for parse before validation issues
    @ApplyIteration(1000)
    def test_jwtfuzz(self, data, state):
        jwt = data.split('.')
        payload = base64.urlsafe_b64decode((jwt[1]+'==').encode('ascii'))
        payload = random_insert(payload,list(set(list(payload))))
        payload = base64.urlsafe_b64encode(payload).strip('=')
        jwt[1] = payload
        return '.'.join(jwt)
    
    # Radamsa as a persistent transform
    def per_mutate(self, data):
        return radamsa(data)

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=10, requestsPerConnection=50, pipeline=0)

    TestFactory = TestLogic(target.req, wordlists)
    for test in TestFactory:
        engine.queue(test, label=TestFactory.get_label())

@UniqueSize(1)
def handleResponse(req, interesting):
    table.add(req)
 

