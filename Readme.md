<h1 align="center">
  <br>
  Haptyc
  <br>
</h1>
<hr>
<h4 align="center">Test Generation Framework</h4>

![demo](L:\home\websec\git\haptyc\img\tag.png)

### What's Haptyc?

Haptyc is a python library which was built to add payload position support and Sniper/Clusterbomb/Batteringram/Pitchfork attack types into Turbo Intruder. While Haptyc accompishes these goals fairly well it also introduces a simpler way to express test sequences in general. While this library was meant to target Turbo Intruder it has no hard dependencies on Turbo Intruder and can be used anywhere one requires test generation in a Python context.

### What are Haptyc tags?

Haptyc tags are tags which a tester can use to annotate an original input payload. A tester can use multiple tags to surround key pieces of data in an HTTP request to wrap it as a positional payload. When tests are being generated Haptyc will parse all the tags in the original payload and generate tests in accordance to the functions associated with the tag names. When Haptyc evaluates a Haptyc tag it will execute the associated tag function (this is called a Haptyc Transform) for a test payload to place in position of the associated tag in the request. Every tag function will recieve a *data* argument and a *state* arugment. The data argument may contain the inner data of the tag or may contain some other test payload sequence. The state argument is a state object associated with the tag where state can be stored between test iterations. Let's review an example.

#### Example 1: Simple list iteration

Original Payload:
```HTTP
GET /animal/[+GuessAnimal]dog[+end] HTTP/1.1
```

Haptyc Class & Haptyc Transform:
```python
from haptyc import *

original = "GET /animal/[+GuessAnimal]dog[+end] HTTP/1.1"

class TestLogic(Transform):
	@ApplyList(["snake","cat","owl","lion"])
	def test_GuessAnimal(self, data, state):
		return data + "?original=" + self.inner() + "&attempt=" + str(state.iter)

TestFactory = TestLogic(original)
for test in TestFactory:
	print(test)
```

Tests Generated:
```HTTP
GET /animal/snake?original=dog&attempt=0 HTTP/1.1
GET /animal/cat?original=dog&attempt=1 HTTP/1.1
GET /animal/owl?original=dog&attempt=2 HTTP/1.1
GET /animal/lion?original=dog&attempt=3 HTTP/1.1
```

In the example above we how one can express tests in a simple way using Haptyc. First the Haptyc library is imported. Second we have defined the original data with our Haptyc tag annotations (GuessAnimal). Next the TestLogic class is defined and extended as a Transform class. Inside this class every method that starts with `test_` will get registered as a Haptyc tag for evalutation in the original payload. We use a logic decorator to apply the state logic for this Haptyc transform. In this case we use the `@ApplyList(list)` decorator to tell Haptyc to generate a test for every item in the specified list and place that item into the Haptyc transform as the data argument. Inside the transform we return a mutated version of the data to insert back into the position of the tag. In this case the mutation is the list item as data concatenated with the data surrounded by the tag (dog) and then concatentated with the iter value in the state object. Lastly the remaining python shows the TestFactory object being created and all tests being generated in a for loop iterator. This is an example of a standard sniper-style attack which targets a single payload position. Next lets look at other style of attacks.

#### Example 2: Clusterbomb

Original Payload:
```HTTP
GET /animal?type=[%type]dog[%end]&name=[%name]fido[%end] HTTP/1.1
```

Haptyc Class & Haptyc Transform:
```python
from haptyc import *

original = "GET /animal?type=[%type]dog[%end]&name=[%name]fido[%end] HTTP/1.1"

class TestLogic(Transform):
	@ApplyList("snake","cat","owl","lion")
	def test_type(self, data, state):
		return data
		
	@ApplyList("Frank", "Lisa", "Jin", "Tooth")
	def test_name(self, data, state):
		return data

TestFactory = TestLogic(original)
for test in TestFactory:
	print(test)
```

Tests Generated:
```HTTP
GET /animal?type=snake&name=Frank HTTP/1.1
GET /animal?type=snake&name=Lisa HTTP/1.1
GET /animal?type=snake&name=Jin HTTP/1.1
GET /animal?type=snake&name=Tooth HTTP/1.1
GET /animal?type=cat&name=Frank HTTP/1.1
GET /animal?type=cat&name=Lisa HTTP/1.1
GET /animal?type=cat&name=Jin HTTP/1.1
GET /animal?type=cat&name=Tooth HTTP/1.1
GET /animal?type=owl&name=Frank HTTP/1.1
GET /animal?type=owl&name=Lisa HTTP/1.1
GET /animal?type=owl&name=Jin HTTP/1.1
GET /animal?type=owl&name=Tooth HTTP/1.1
GET /animal?type=lion&name=Frank HTTP/1.1
GET /animal?type=lion&name=Lisa HTTP/1.1
GET /animal?type=lion&name=Jin HTTP/1.1
GET /animal?type=lion&name=Tooth HTTP/1.1
```

Example 1 showed how to evaluate transforms sniper style by using the '+' sign annotation in the tag ``[+tag][+end]``. Example 2 shows how we can use 2 transforms/positions to conduct a clusterbomb-style of attack. As you can see we use 2 separate transform tags called ``[%type][%end]`` and ``[%name][%end]``. The '%' sign tells Haptyc to evaluate these transforms clusterbomb-style, for every payload in the first transform create a test with the payload from the second transform. The test count is the number of tests of every transform involved multiplied by each other.

#### Example 3: Pitchfork/BatteringRam

Using the same exact python code we can switch the attack style from clusterbomb to pitchfork by changing the '%' to a '#'. Pitchfork style attacks will place the postion payload all in parallel. The test count is the lowest number of tests given of all involved transforms.  

Original Payload:
```HTTP
GET /animal?type=[#type]dog[#end]&name=[#name]fido[#end] HTTP/1.1
```

Tests Generated:
```HTTP
GET /animal?type=snake&name=Frank HTTP/1.1
GET /animal?type=cat&name=Lisa HTTP/1.1
GET /animal?type=owl&name=Jin HTTP/1.1
GET /animal?type=lion&name=Tooth HTTP/1.1
```

#### Example 4: Persistent Transforms

Original Payload:
```HTTP
GET /animal?type=dog&id=[+idor]0[+end]&process=[@randbool]False[@end] HTTP/1.1
```

Haptyc Class & Haptyc Transform:
```python
from haptyc import *
import random

original = "GET /animal?type=dog&id=[+idor]0[+end]&process=[@randbool]False[@end] HTTP/1.1"

class TestLogic(Transform):
        @ApplyIteration(10)
        def test_idor(self, data, state):
                return str(state.iter)

        def per_randbool(self, data):
                return random.choice(["True", "False"])

TestFactory = TestLogic(original)
for test in TestFactory:
        print(test)
```

Tests Generated:
```HTTP
GET /animal?type=dog&id=0&process=False HTTP/1.1
GET /animal?type=dog&id=1&process=True HTTP/1.1
GET /animal?type=dog&id=2&process=False HTTP/1.1
GET /animal?type=dog&id=3&process=True HTTP/1.1
GET /animal?type=dog&id=4&process=False HTTP/1.1
GET /animal?type=dog&id=5&process=True HTTP/1.1
GET /animal?type=dog&id=6&process=False HTTP/1.1
GET /animal?type=dog&id=7&process=True HTTP/1.1
GET /animal?type=dog&id=8&process=False HTTP/1.1
GET /animal?type=dog&id=9&process=False HTTP/1.1
```

Persistent transforms are denoted by the '@' sign and the transform functions always start with `per_` this is because these tranforms are not iterative, they don't create tests or keep state. These transforms are just naive transformation which you can apply anywhere in the payload for a state-less transformation without affecting the stateful transforms. Since they don't prescribe any tests you cannot generate tests with persistent transforms alone, they are meant to be mixed with iterative transforms. In the example above we have a 10-test snipe style transform placing an incrementing id. Also we have a persistant transform which places a random boolean into its position.


#### Example 5:  Using state and state.init

There may be cases where prior to the start of a test sequence the tester may want to perform some processing/initialization. To support this Haptyc executes all involved transforms for an initialization phase prior to executing the transform for test generation. This initialization step can be used for performing whatever initialization the tester requires and placing it into the state object. For this the tester can use `state.init` as a boolean to determine if the execution is in initialization. Any returned data from the initialization step will be ignored.

Original Payload:
```HTTP
GET /animal?data=[+b64mutate]SGVsbG8gSGFja2VyIQ==[+end] HTTP/1.1
```

Haptyc Class & Haptyc Transform:
```python
from haptyc import *
import base64

original = "GET /animal?data=[+b64mutate]SGVsbG8gSGFja2VyIQ==[+end] HTTP/1.1"

class TestLogic(Transform):
        @ApplyIteration(10)
        def test_b64mutate(self, data, state):
                if state.init:
                        state.decoded = base64.b64decode(data)
                        return
                return base64.b64encode(random_insert(state.decoded, ["'"]))

TestFactory = TestLogic(original)
for test in TestFactory:
        print(test)
```

Tests Generated:
```HTTP
GET /animal?data=SGVsbG8gSCdhY2tlciE= HTTP/1.1
GET /animal?data=SGVsbG8gSGFja2VyISc= HTTP/1.1
GET /animal?data=SGVsbG8gSGFjaydlciE= HTTP/1.1
GET /animal?data=SGVsbG8gSGEnY2tlciE= HTTP/1.1
GET /animal?data=SCdlbGxvIEhhY2tlciE= HTTP/1.1
GET /animal?data=SGVsbG8gSGFjaydlciE= HTTP/1.1
GET /animal?data=SGVsbG8gSGFja2VyISc= HTTP/1.1
GET /animal?data=SCdlbGxvIEhhY2tlciE= HTTP/1.1
GET /animal?data=SGVsbG8gSGFjJ2tlciE= HTTP/1.1
GET /animal?data=SGVsbG8gSGFjJ2tlciE= HTTP/1.1
```

In the example above the test uses `state.init` to base64 decode the wrapped inner payload only once at the beginning of the test sequence and store that result into `state.decoded`. Then for all normal test generation executions `state.decoded` is used as the decoded inner data to be processed. This type of pattern is useful to improve the performance of your transform due to the fact that only 1 decode occurs at the beginning (vs decoding the same payload at the generation of every test).

### Documentation

#### Tag Types
1) `[+tag]inner[+end]` - Sniper style iterative transform
2) `[%tag]inner[%end]` - Clusterbomb style iterative transform
3) `[#tag]inner[#end]` - Batteringram/Pitchfork style iterative transform
4) `[@tag]inner[@end]` - Stateless persistant transform

#### Logic Decorators
| Name               | Arguments | `data` input | Description |
|--------------------|----------|--------------|-------------|
| @ApplyIteration(n) | n= # of Iterations      | inner value of the haptyc tag| Logic to generate N tests with inner as data |
| @ApplyRange(b,e,s=1)| b = begin value, e = max value, s = step| generated value of the range| Logic to generate a test for every value stepped with the value given as data |
| @ApplyList(L)      | L = python list| item of the list| Logic to generate a test for every value in the list given as data |
| @ApplyFilelist(path)| path = filesystem path|item of the list| Logic to generate a test for every value in the filelist given as data|
| @ApplyPayloads(name)| name = builtin list name|item of the list|Logic to generate a test for every value in the built-in list given as data|

#### Haptyc Class Decorators
| Name               | Arguments | Description |
|--------------------|----------|--------------|
| @CloneTransform(srcname, destname) | srcname=string of a transform method copy from, destname=string of a non-existent transform method to copy into| CloneTransform is used to copy the implementation of one transform into another namespace without needing to copy/paste. This is useful in '%' and '#' style attacks when you need to re-use the same transform implementation in multiple positions|

#### Transform Class Helper Methods
| Name                | Description |
|----------------|-------------|
| self.inner()                | Retrives the inner payload of the tag|
|  self.stop() | Will immediately stop test generation of that transform|
|  self.me() | Will return the name of the current transform context|
|  self.set_label(label) | Will set the label for this current test|
|  self.get_label(label) | Will get the label for this current test|

#### Transform Helper State Attributes
| Name                | Description |
|----------------|-------------|
|  state.iter | Current iteration count of the transform (0-based) |
|  state.init | Boolean that indicates if in the initialization stage |

#### Helper Mutation Functions
| Name                | Description |
|----------------|-------------|
|  radamsa(data) | This function will execute radamsa on the input data and returns its result (radamsa is required to be installed) |
|  index_insert(data, list, index) | This function will insert a payload from the list into the supplied data at the supplied index |
|  random_insert(data, list) | This function will insert a payload from the list into the supplied data at a random index |

#### Bulitin Wordlists
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

### How to install

1) Clone this repo
2) In bash execute `./install.sh <directory with turbo-intruder-all.jar>`
3) In Burp reload Turbo Intruder
4) (Optional) Installl radamsa via [https://gitlab.com/akihe/radamsa](https://gitlab.com/akihe/radamsa)
