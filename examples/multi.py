from haptyc import *
from base64 import b64encode, b64decode

# With CloneTransform you can duplicate any iterative transform into a new test name
@CloneTransform("test_h3", "test_h3c")
class TestLogic(Transform):
    # ApplyIteration is simple iteration logic that will issue N number of tests
    # the data argument contains the data which the h1 tag wraps
    @ApplyIteration(20)
    def test_h1(self, data, state):
        data = b64decode(data)
        data = random_insert(data,list("'"))
        data = b64encode(data)
        return data

    # ApplyRange is simple iteration logic that will test for each value generated
    # by this range. the data argument contains the value of the range operation
    @ApplyRange(0,5,1)
    def test_h2(self, data, state):
        return data

    # ApplyList is simple iteration logic that will test for each value in a list
    # the data argument contains an element of the list
    @ApplyList(["cat","dog","mouse","racoon","snake"])
    def test_h3(self, data, state):
        return data
    
    # ApplyFilelist is simple iteration logic that will test for each value in a wordfile
    # specified by the file path. the data argument contains an element of the wordfile
    @ApplyFilelist("D:\\list.txt")
    def test_h4(self, data, state):
        return data + self.inner()
    
    # ApplyPayloads is simple iteration logic that will test for each value in a
    # builtin wordfile specified by the keyword. the data argument contains an 
    # element of the builtin wordfile
    @ApplyPayloads("dirsearch")
    def test_basco5(self, data, state):
        return data.replace('%EXT%', 'pdf')
    
    # methods that start with "per_" are called persistant transforms, they do not have state
    # and they always execute with every issued test from a iterative transform
    def per_mutate(self, data):
        return radamsa(data)

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, requestsPerConnection=1, pipeline=0)

    TestFactory = TestLogic(target.req)
    for test in TestFactory:
        engine.queue(test)

def handleResponse(req, interesting):
    table.add(req)
 
"""
Example builtin ApplyPayloads wordlists

@ApplyPayloads("0-9")
@ApplyPayloads("10 letter words")
@ApplyPayloads("11 letter words")
@ApplyPayloads("12 letter words")
@ApplyPayloads("3 letter words")
@ApplyPayloads("4 letter words")
@ApplyPayloads("5 letter words")
@ApplyPayloads("6 letter words")
@ApplyPayloads("7 letter words")
@ApplyPayloads("8 letter words")
@ApplyPayloads("9 letter words")
@ApplyPayloads("a-z")
@ApplyPayloads("CGI scripts")
@ApplyPayloads("Directories - long")
@ApplyPayloads("Directories - short")
@ApplyPayloads("dirsearch")
@ApplyPayloads("Extensions - long")
@ApplyPayloads("Extensions - short")
@ApplyPayloads("Filenames - long")
@ApplyPayloads("Filenames - short")
@ApplyPayloads("Format strings")
@ApplyPayloads("Form field names - long")
@ApplyPayloads("Form field names - short")
@ApplyPayloads("Form field values")
@ApplyPayloads("Fuzzing - full")
@ApplyPayloads("Fuzzing - JSON_XML injection")
@ApplyPayloads("Fuzzing - out-of-band")
@ApplyPayloads("Fuzzing - path traversal")
@ApplyPayloads("Fuzzing - path traversal (single file)")
@ApplyPayloads("Fuzzing - quick")
@ApplyPayloads("Fuzzing - SQL injection")
@ApplyPayloads("Fuzzing - template injection")
@ApplyPayloads("Fuzzing - XSS")
@ApplyPayloads("HTTP headers")
@ApplyPayloads("HTTP verbs")
@ApplyPayloads("IIS files and directories")
@ApplyPayloads("Interesting files and directories")
@ApplyPayloads("Local files - Java")
@ApplyPayloads("Local files - Linux")
@ApplyPayloads("Local files - Windows")
@ApplyPayloads("Passwords")
@ApplyPayloads("Server-side variable names")
@ApplyPayloads("Short words")
@ApplyPayloads("SSRF targets")
@ApplyPayloads("User agents - long")
@ApplyPayloads("User agents - short")
@ApplyPayloads("Usernames")
"""
