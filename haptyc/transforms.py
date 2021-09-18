# Project: Haptyc
# Author: Evan Custodio (@defparam)
#
# Copyright 2021 Evan Custodio
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import random
import string
import subprocess
import os, sys
import json
import copy
import functools
import types
import glob

global IS_JYTHYON
global IS_BURP

try:
    import burp.RequestEngine
    from java.lang import ClassLoader
    from java.io import InputStreamReader, BufferedReader
    IS_BURP = True
except:
    IS_BURP = False

try: # check if we are in a jython context
    import java.lang
    IS_JYTHYON = True
    def is_win():
        return ("windows" in java.lang.System.getProperty("os.name").lower())
except:
    IS_JYTHYON = False
    def is_win():
        return ("nt" == os.name)
        
def GetDataFromStream(stream):
    reader = BufferedReader(InputStreamReader(stream))
    line = ""
    while True:
        data = reader.readLine()
        if data == None:
            if line == "":
                return line
            return line[0:-1]
        line += data + "\n"

def bytes_to_str(data):
    return "".join([chr(ord(i)) for i in data])
    
def str_to_bytes(data):
    return b"".join([chr(ord(i)) for i in data])

# We use this helper function to generate a high entropy random string for
# text replacement
def get_random_string(length):
    result_str = ''.join(random.choice(string.ascii_letters) for i in range(length))
    return result_str
    
def get_transform_type(funcname):
    if ((len(funcname) >= 6) and (funcname[0:5] == "test_")):
        return 0
    elif ((len(funcname) >= 5) and (funcname[0:4] == "per_")):
        return -1

def radamsa(data):
    if is_win():
        stdout, stderr = subprocess.Popen(["wsl","radamsa", "-"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate(str_to_bytes(data))
    else:
        stdout, stderr = subprocess.Popen(["radamsa", "-"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate(str_to_bytes(data))
    # Bug: we have to do this replace of %s because turbo intruder scans for %s replacements
    # there is no way to turn this off in turbo intruder without recompiling it
    return bytes_to_str(stdout).replace(r"%s",r"%x")

def random_insert(data, chars):
    if type(chars) != list:
        raise Exception("Second argument must be a list of strings")
    char = random.choice(chars)
    data = list(data)
    data.insert(random.randint(0,len(data)), char)
    return ''.join(data)
    
def index_insert(data, chars, index):
    if type(chars) != list:
        raise Exception("Second argument must be a list of strings")
    if ((index < 0) or (index > len(data))):
        raise StopIteration
    char = random.choice(chars)
    data = list(data)
    data.insert(index, char)
    return ''.join(data)

def CloneTransform(src, dest):
    def decorator(orig):
        # keep a copy of the original ctor
        ctor = orig.__init__
    
        def __init__(self, *args, **kws):
            # this is our copy func, we explicitly make copies of all of the function parts that we use
            def copy_func(f, fname=None, fclosure=None):
                g = types.FunctionType(f.func_code, f.func_globals, fname or f.func_name,
                                       f.func_defaults,
                                       fclosure or f.func_closure)
                g.__dict__.update(f.__dict__)
                g = functools.update_wrapper(g, f)
                return g
        
            # We use this nifty call to build cells with content for closure objects
            def build_cell(contents):
                fn = (lambda x: lambda: x)(contents)
                return fn.__closure__[0]

            # grab the source func from string
            src_func = getattr(self, src)
            
            # lets take care of closures if they exist
            if src_func.func_closure != None:
                newclo = ()
                for cell in src_func.func_closure:
                    if callable(cell.cell_contents) and (cell.cell_contents.func_name == src):
                        # create a copy of the source closure cell func
                        newfunc = copy_func(cell.cell_contents,dest)
                        # now that everything has been cloned, rename the destination func_name with the new name
                        newfunc.func_name = dest
                        newclo += (build_cell(newfunc),)
                    else:
                        newclo += (cell,)
                tmpfunc = types.MethodType(copy_func(src_func,src_func.func_name,newclo),self)
            else:
                # we make a copy of the function with its own closure object and assign it to
                newfunc = copy_func(src_func,dest)
                newfunc.func_name = dest
                tmpfunc = types.MethodType(newfunc,self)
                
            
            # assign it to the instance
            setattr(self, dest, tmpfunc)

            # call the original constructor
            ctor(self, *args, **kws)
        
        # assign this new constructor wrapper to the class object
        orig.__init__ = __init__
              
        return orig
    return decorator


# This is our base transform class, all derivative transforms must inherit from it
class Transform():
    def __init__(self, req, wordlists=None):
        # We initialize the class with instance specific variables
        self._data = req # This is the input raw data
        self._wordlists = wordlists # turbo intruder wordlists
        self._iterative_transformers = []
        self._persistent_transformers = []
        self._iterative_operations = []
        self._iterative_operation_index = 0
        self._persistent_operations = []
        self._persistent_operation_index = 0
        self._iterative_operation_type = None
        self._transform_context = "" # currently running transform
        self._trans_types = ["Sniper", "Battering Ram/Pitchfork", "Clusterbomb"]
        self._iterative_mode = False
        self._randomize_lists = False
        self._label  = ""
        self._gstate = {}

        # parse all attributes of this class looking for iterative and persistent transformers
        for item in dir(self):
            if ((len(item) >= 6) and (item[0:5] == "test_")):
                self._iterative_transformers += [item[5:]]
            elif ((len(item) >= 5) and (item[0:4] == "per_")):
                self._persistent_transformers += [item[4:]]
                
        # With all transformers identfied, now parse the tagged data
        self._parse()
        
    # return the name of our transform we are currently running
    def me(self):
        return self._transform_context
    
    # return the inner text of the transform we are currently running    
    def inner(self):
        transform_name = self._transform_context
        return self.get_input(transform_name)
        
    # set the randomize lists flag
    def randomize_lists(self, val):
        self._randomize_lists = val
        
    # return this transformer's state object
    def get_state(self):
        class state(object):
            pass
            
        # the key into gstate is the transform name
        # because we only look back a frame the caller
        # must be the transform function
        key = self._transform_context
        
        # if we don't yet have state for this transform
        # then create it and store it
        if key not in self._gstate:
            stateobj = state()
            self._gstate[key] = stateobj
        else:
            stateobj = self._gstate[key]
            
        # return the state object
        return stateobj
        
    def stop(self):
        raise StopIteration
          
    def get_label(self):
        return self._label
    
    def set_label(self,label):
        self._label = label
            
    def get_input(self,transform):
        input = None
        for operation in (self._iterative_operations+self._persistent_operations):
            if operation['funcname'] == transform:
                if input != None:
                    raise Exception("Getting input on multi-instance transforms is not allowed.")
                input = operation['data']
        if input == None:
            raise Exception("Transform function '%s' has no found instance."%(transform))
        return input
        
    def get_output(self, transform):
        if (self._iterative_mode):
            raise Exception("Getting a transform output from within an iterative transform is not allowed.")
        if (get_transform_type(transform) == -1):
            raise Exception("Getting a persistent transform output is not allowed.")
        output = None
        for operation in self._iterative_operations:
            if operation['funcname'] == transform:
                if output != None:
                    raise Exception("Getting output on multi-instance transforms is not allowed.")
                output = operation['cached']
        if output == None:
            raise Exception("Transform function '%s' has no found instance."%(transform))
        return output 
        
    # when evaluating a transform as an iterator, python first calls this base function
    def __iter__(self):
        self._operationindex = 0
        
        # Every iterative transformer provides its own iteration routine
        # If there exists at least 1 iterative transformer, call the transformer
        # with the init flag set to True so that it can set up its initial state
        if len(self._iterative_operations):
            if self._iterative_operation_type == 0:
                operation = self._iterative_operations[0]
                self._transform_context = "test_" + operation['transformer']
                state = self.get_state()
                state.init = True
                getattr(self, self._transform_context)(operation['data'], state)
            else:
                for operation in self._iterative_operations:
                    self._transform_context = "test_" + operation['transformer']
                    state = self.get_state()
                    state.init = True
                    getattr(self, self._transform_context)(operation['data'], state)

            
        # Return the class instance itself as an iterator
        return self
    
    def _get_tags(self, transformer, trans_type):
        if (trans_type == 0): # sniper
            return ("[+"+transformer+']', "[+end]")
        elif (trans_type == 1): # battering ram/Pitchfork
            return ("[#"+transformer+']', "[#end]")
        elif (trans_type == 2): # clusterbomb
            return ("[%"+transformer+']', "[%end]")
        raise Exception("Unknown Iterative Transformer Type")
        
    
    
    # This is the function in charge of processing all found iterative transformers
    # in the body of data
    def _parse_iterative(self, dat):
        endtags = ["[+end]","[#end]","[%end]"]
        self._iterative_operation_type = -1
        for i in range(len(endtags)):
            if endtags[i] in dat:
                if ((self._iterative_operation_type > -1) and (self._iterative_operation_type != i)):
                    raise Exception("Cannot mix iterative transformer types: %s and %s"%(self._trans_types[self._iterative_operation_type],self._trans_types[i]))
                self._iterative_operation_type = i
        
        # There appears to be no iterative transformers, return the payload as is for persistent transformer parsing
        if self._iterative_operation_type == -1:
            return dat
    
        # we first iterate through all known iterative transformers
        for transformer in self._iterative_transformers:
            trans_type = self._iterative_operation_type
            # we prep the tag literals for search
            starttag, endtag = self._get_tags(transformer, trans_type)

            curr = 0
            while 1:
                # We first look for any sign of syntax open with a valid transformer name
                # if none is found we break and loop into the next transformer
                s = dat.find(starttag,curr)

                if s == -1:
                    break
                    
                if ((trans_type == 1) or (trans_type == 2)):
                    for operation in self._iterative_operations:
                        if operation["transformer"] == transformer:
                            raise Exception("Cannot have more than 1 transformer instantiation of the same name in ram/cluster mode(%s)"%(transformer))
                    
                
                # Next we make sure we find a proper end tag so that we understand how to
                # parse the data we want to transform, we raise exception if none is found
                e = dat.find(endtag,s)
                
                if (e == -1):
                    raise Exception("Could Not Parse Iterative Transformation End Tag")
                    
                # Back to open tag processing, locate the end bracket so we can parse
                # the inner text and also the inner tag
                sc = -1
                for i in range(s,e):
                    if dat[i] == ']':
                       sc = i
                       break
                       
                # sc contains the location of the close bracket, if none is found raise exception
                if sc == -1:
                    raise Exception("Could Not Parse Iterative Transformation Start Tag")
                
                # With the start tag end known, we can parse the inner text
                inner = dat[sc+1:e]
                
                
                # Lets produce a high-entropy unique alias for future text replacement
                alias = get_random_string(32)
                
                # validate tag annotations for multiple interative transformers
                annotations = dat[s+2:sc]
                
                # BUG (9/8/21): cumulative iterative transforms at the moment are broken and 
                # not possible until the tag parsing logic is fixed
                #
                # If the inner tag annotions contain a ; character then we know that we are dealing
                # with cumulative iterative transformers, lets process each of them
                # This is only allowed for sniper type iterative transformers
                if ((';' in annotations) and (trans_type == 0)):
                    # split the inner tag text with ; as a delimiter, and iterate through each
                    transformers = annotations.split(';')
                    for trans in transformers:
                        # clean up any whitespace and ignore empty tranformer names
                        trans = trans.strip()
                        if trans == "":
                            continue
                            
                        # Validate that a given annotated transformer name indeed exists
                        # otherwise raise exception
                        if trans not in self._iterative_transformers:
                            raise Exception("Invalid Iterative Transformer: %s"%(trans))
                            
                        # for each valid transformer, add them to the operation list
                        # with its alias and original inner data
                        funcname = "test_"+trans
                        operation = {"transformer":trans,"funcname":funcname,"alias":alias,"data":inner,"cached":None}
                        self._iterative_operations += [operation]
                else:
                    # If this is not a cumulative iterative transformer then validate that
                    # the inner tag text exactly matches the transformer name
                    if transformer.strip() != annotations.strip():
                        curr = s+1
                        continue
                        
                    # Add this single transformer operation to the list with alias and
                    # original inner data
                    funcname = "test_"+transformer
                    operation = {"transformer":transformer,"funcname":funcname,"alias":alias,"data":inner,"cached":None}
                    self._iterative_operations += [operation]
                
                # As we find valid transformer markup, lets replace the entire markup
                # with the high entropy alias on the data we are parsing
                dat = dat[0:s] + alias + dat[e+len(endtag):]
       
        # return the data with alias decorations
        return dat

    # This is the function in charge of processing all found persistent transformers
    # in the body of data        
    def _parse_persistent(self, dat):
        # we first iterate through all known persistent transformers
        for transformer in self._persistent_transformers:
            # we prep the tag literals for search
            starttag = "[@"+transformer+']'
            endtag = "[@end]"
            curr = 0
            while 1:
                # We first look for any sign of syntax open with a valid transformer name
                # if none is found we break and loop into the next transformer
                s = dat.find(starttag,curr)
                if s == -1:
                    break
                    
                # Next we make sure we find a proper end tag so that we understand how to
                # parse the data we want to transform, we raise exception if none is found
                e = dat.find(endtag,s)
                if (e == -1):
                    raise Exception("Could Not Parse Persistent Transformation End Tag")
                    
                # Back to open tag processing, locate the end bracket so we can parse
                # the inner text and also the inner tag
                sc = -1
                for i in range(s,e):
                    if dat[i] == ']':
                       sc = i
                       break
                # sc contains the location of the close bracket, if none is found raise exception
                if sc == -1:
                    Exception("Could Not Parse Persistent Transformation Start Tag")

                # With the start tag end known, we can parse the inner text
                inner = dat[sc+1:e]
                
                # Lets produce a high-entropy unique alias for future text replacement
                alias = get_random_string(32)
                
                # validate tag annotations for multiple Persistent transformers
                annotations = dat[s+2:sc]
                
                # BUG (9/8/21): piped persistent transformers at the moment are broken and 
                # not possible until the tag parsing logic is fixed
                #
                # If the inner tag annotions contain a | character then we know that we are dealing
                # with piped persistent transformers, lets process each of them
                if '|' in annotations:
                    # split the inner tag text with | as a delimiter, and iterate through each
                    transformers = annotations.split('|')
                    for trans in transformers:
                        # clean up any whitespace and ignore empty tranformer names
                        trans = trans.strip()
                        if trans == "":
                            continue

                        # Validate that a given annotated transformer name indeed exists
                        # otherwise raise exception    
                        if trans not in self._persistent_transformers:
                            raise Exception("Invalid Persistent Transformer: %s"%(trans))
                            
                    # add this valid piped persistent transformer operation as a single group 
                    # with its alias and original inner data        
                    operation = {"transformer":annotations, "alias":alias, "data":inner}
                    self._persistent_operations += [operation]
                else:
                    # If this is not piped persistent transformers then validate that
                    # the inner tag text exactly matches the transformer name
                    if transformer.strip() != annotations.strip():
                        curr = s+1
                        continue
                     
                    # Add this single transformer operation to the list with alias and
                    # original inner data
                    operation = {"transformer":transformer,"funcname":"per_"+transformer ,"alias":alias, "data":inner}
                    self._persistent_operations += [operation]
                    
                # As we find valid transformer markup, lets replace the entire markup
                # with the high entropy alias on the data we are parsing 
                dat = dat[0:s] + alias + dat[e+len(endtag):]
        # return the data with alias decorations
        return dat
        
    # This parse function called by the construct on instance creation
    def _parse(self):
        # Grap the object data
        dat = self._data
        # Parse and annotate all iterative transformers
        dat = self._parse_iterative(dat)
        # Parse and annotate all persistent transformers
        dat = self._parse_persistent(dat)
        # replace the object data with the new decorated data
        self._data = dat
        
    # This function is processes the decorated data replacing all iterative transformers
    # with its original data
    def _evaluate_default_iterative_transformers(self,dat):
        for operation in self._iterative_operations:
            dat = dat.replace(operation['alias'], operation['data'])
        return dat
        
    # This function processes the decorated data replacing all persistent transformers
    # with its original data processed through each associated transforming function
    def _evaluate_persistent_transformers(self,dat):
        # process all persistent operations
        for operation in self._persistent_operations:
            # piped transformer flow
            if '|' in operation['transformer']:
                # build a pipe chain of functions
                chain = operation['transformer'].split('|')
                # start by caching the original data
                current_data = operation['data']
                # for each annotated persistent function
                for trans in chain:
                    # clean it
                    trans = trans.strip()
                    if trans == '':
                        continue
                    # call the associated processing function to transform the current_data variable
                    self._transform_context = "per_" + trans
                    current_data = getattr(self, self._transform_context)(current_data)
            # non-piped persistent transformer flow
            else:
                # There exists only a single transformer, call the function on the operation data
                self._transform_context = "per_" + operation['transformer']
                current_data = getattr(self, self._transform_context)(operation['data'])
                
            # for every operation piped or not, take the current_data in its transformed format
            # and replace the decorated alias with it
            dat = dat.replace(operation['alias'], current_data)
        # return the evaluated data
        return dat
        
    def _next_sniper(self):
        while(1):
            # Starting at the first iterative operation, grab the operation
            operation = self._iterative_operations[self._iterative_operation_index]
            
            # enclose in a try block to catch when the iterative transformer is complete
            try:
                # Call the associated function to apply the transformation on the data
                self._transform_context = "test_" + operation['transformer']
                state = self.get_state()
                state.init = False
                transformed = getattr(self, self._transform_context)(operation['data'],state)
                
                # Replace the alias decoration in the data with the transformed data
                alias = operation['alias']
                data = self._data.replace(alias, transformed)
                operation['cached'] = transformed
                
            # We came to the completion of given iterative operation
            except StopIteration:
                # Go to the next iterative operation
                self._iterative_operation_index += 1
                
                # If there are no more then officially yield StopIteration
                if self._iterative_operation_index == len(self._iterative_operations):
                    raise StopIteration
                    
                operation = self._iterative_operations[self._iterative_operation_index]
                    
                # We moved to a new iterative operation, call it with the init value True
                # so that the iterative transform can initialize its state
                self._transform_context = "test_" + operation['transformer']
                state = self.get_state()
                state.init = True
                getattr(self, self._transform_context)(operation['data'],state)
                continue
                
            # At this point we have replaced the active iterative transform alias with transformed data
            # now loop through all other inactive iterative transforms replacing their decorations with
            # original data
            for i in range(len(self._iterative_operations)):
                if i == self._iterative_operation_index:
                    continue
                data = data.replace(self._iterative_operations[i]['alias'], self._iterative_operations[i]['data'])
                self._iterative_operations[i]['cached'] = self._iterative_operations[i]['data']


            return data
            
    def _next_ram(self):
        data = self._data
        stop = False
        for operation in self._iterative_operations:
            try:
                # Call the associated function to apply the transformation on the data
                self._transform_context = "test_" + operation['transformer']
                state = self.get_state()
                state.init = False
                operation["cached"] = getattr(self, self._transform_context)(operation['data'],state)
                
                # Replace the alias decoration in the data with the transformed data
                alias = operation['alias']
                data = data.replace(alias, operation["cached"])
            except StopIteration:
                stop = True
        if stop:
            raise StopIteration
        return data
                
        
    def _next_cluster(self):
        data = self._data
        if (len(self._iterative_operations) > 1):
            for i in range(1,len(self._iterative_operations)):
                operation = self._iterative_operations[i]
                if operation["cached"] == None:
                    try:
                        # Call the associated function to apply the transformation on the data
                        self._transform_context = "test_" + operation['transformer']
                        state = self.get_state()
                        state.init = False
                        operation["cached"] = getattr(self, self._transform_context)(operation['data'],state)                    
                    # We came to the completion of given iterative operation
                    except StopIteration:
                        operation["cached"] = operation["data"]
        
        self._iterative_operation_index = 0
        while(1):
            # Starting at the first iterative operation, grab the operation
            operation = self._iterative_operations[self._iterative_operation_index]
            
            # enclose in a try block to catch when the iterative transformer is complete
            try:
                # Call the associated function to apply the transformation on the data
                self._transform_context = "test_" + operation['transformer']
                state = self.get_state()
                state.init = False
                operation["cached"] = getattr(self, self._transform_context)(operation['data'],state)
                
                # Replace the alias decoration in the data with the transformed data
                alias = operation['alias']
                data = data.replace(alias, operation["cached"])
                
            # We came to the completion of given iterative operation
            except StopIteration:
                # Wrap
                self._transform_context = "test_" + operation['transformer']
                state = self.get_state()
                state.init = True
                getattr(self, self._transform_context)(operation['data'],state)
                state = self.get_state()
                state.init = False
                operation["cached"] = getattr(self, self._transform_context)(operation['data'],state)
                alias = operation['alias']
                data = data.replace(alias, operation["cached"])
            
                # Go to the next iterative operation
                self._iterative_operation_index += 1
                
                # If there are no more then officially yield StopIteration
                if self._iterative_operation_index == len(self._iterative_operations):
                    raise StopIteration
                continue
                
            for i in range(self._iterative_operation_index+1,len(self._iterative_operations)):
                operation = self._iterative_operations[i]
                alias = operation['alias']
                data = data.replace(alias, operation["cached"])
                
            return data
    

        
    # Our formal python iterator which evaluates all transforms
    def next(self):
        # Clear our label
        self._label = ""
        
        # if no iterative operations exist then theres noting to return
        if (len(self._iterative_operations) == 0):
                raise StopIteration
                
        # When processing iterative transforms, set the iterative mode variable        
        self._iterative_mode = True
        if self._iterative_operation_type == 0:
            data = self._next_sniper()
        elif self._iterative_operation_type == 1:
            data = self._next_ram()
        elif self._iterative_operation_type == 2:
            data = self._next_cluster()
        # When done processing iterative transforms, reset the iterative mode variable        
        self._iterative_mode = False
                
        # As last step before we yield back this data, process any persistent tranformers that may
        # exist in the data
        return self._evaluate_persistent_transformers(data)

    # On eval we process all iterative transforms with their
    # original data, and we process all persistent transforms with their transformed data
    def eval(self):
        data = self._data
        data = self._evaluate_default_iterative_transformers(data)
        data = self._evaluate_persistent_transformers(data)
        return data

def ApplyRange(start,end,step=1):
    def decorator(func):
        if get_transform_type(func.func_name) == -1: # This is a persistent transform
            raise Exception("ApplyRange Cannot Modify Persistent Transforms")
        else: # Otherwise this is an iterative transform
            if step == 0:
                raise Exception("ApplyRange step value must not be zero")
            def count_impl_iter(self, data, state):

                if state.init:
                    state.curr = start
                    state.end  = end
                    state.step = step
                    func(self, str(state.curr), state)
                    return
                    
                if (state.step > 0):
                    if (state.curr < state.end):
                        data = state.curr
                        state.curr += state.step
                        return func(self, str(data), state)
                    else:    
                        raise StopIteration 
                else:
                    if (state.curr > state.end):
                        data = state.curr
                        state.curr += state.step
                        return func(self, str(data), state)
                    else:    
                        raise StopIteration                     
            return count_impl_iter
    return decorator
    
def ApplyIteration(iteration):
    def decorator(func):
        if get_transform_type(func.func_name) == -1: # This is a persistent transform
            raise Exception("ApplyIteration Cannot Modify Persistent Transforms")
        else: # Otherwise this is an iterative transform
            def iteration_impl_iter(self, data, state):

                if state.init:
                    state.iter = 0
                    state.limit = iteration
                    func(self, data, state)
                    return
                    
                if (state.iter < state.limit):
                    ret = func(self, data, state)
                    state.iter += 1
                    return ret
                else:    
                    raise StopIteration  
            return iteration_impl_iter
    return decorator

def ApplyObserved(func):
    if get_transform_type(func.func_name) == -1: # This is a persistent transform
        raise Exception("ApplyList Cannot Modify Persistent Transforms")
    else: # Otherwise this is an iterative transform
        def iteration_impl_list(self, data, state):

            if state.init:
                state.iter = 0
                if self._wordlists == None:
                    raise Exception("Transform instance was not given a burp wordlists object")
                state.elements = list(self._wordlists.getObservedWords())
                if (self._randomize_lists):
                    random.shuffle(state.elements)
                state.index = 0
                func(self, data, state)
                return
                
            if (state.index < len(state.elements)):
                data = state.elements[state.index]
                state.index += 1
                ret = func(self, data, state)
                state.iter += 1
                return ret
            else:    
                raise StopIteration  
        return iteration_impl_list
    
def ApplyList(*Lists):
    def decorator(func):
        if get_transform_type(func.func_name) == -1: # This is a persistent transform
            raise Exception("ApplyList Cannot Modify Persistent Transforms")
        else: # Otherwise this is an iterative transform
            def iteration_impl_list(self, data, state):

                if state.init:
                    state.iter = 0
                    state.elements = []
                    for list in Lists:
                        state.elements += list
                    if (self._randomize_lists):
                        random.shuffle(state.elements)
                    state.index = 0
                    func(self, data, state)
                    return
                    
                if (state.index < len(state.elements)):
                    data = state.elements[state.index]
                    state.index += 1
                    ret = func(self, data, state)
                    state.iter += 1
                    return ret
                else:    
                    raise StopIteration  
            return iteration_impl_list
    return decorator
    
def ApplyFilelist(*paths):
    def decorator(func):
        if get_transform_type(func.func_name) == -1: # This is a persistent transform
            raise Exception("ApplyList Cannot Modify Persistent Transforms")
        else: # Otherwise this is an iterative transform
            def iteration_impl_list(self, data, state):
                    
                if state.init:
                    state.iter = 0
                    state.elements = []
                    for path in paths:
                        with open(path) as f:
                            elems = f.read().split('\n')
                            elemsf = []
                            for i in range(len(elems)):
                                if elems[i].strip() == "": continue
                                elemsf += [elems[i].strip()]
                            state.elements += elemsf
                    if (self._randomize_lists):
                        random.shuffle(state.elements)
                    state.index = 0
                    func(self, data, state)
                    return
                    
                if (state.index < len(state.elements)):
                    data = state.elements[state.index]
                    state.index += 1
                    ret = func(self, data, state)
                    state.iter += 1
                    return ret
                else:    
                    raise StopIteration  
            return iteration_impl_list
    return decorator
 
def ApplyPayloads(*keywords):
    if IS_BURP:
        stream = burp.RequestEngine.getResourceAsStream("/Lib/haptyc/PayloadStrings/manifest.txt")
        manifest = GetDataFromStream(stream).replace(".pay","").split("\n")
    else:
        manifestFile = os.path.dirname(__file__) + "/PayloadStrings/manifest.txt"
        manifest = open(manifestFile).read().replace(".pay","").split("\n")
    
    for keyword in keywords:
        if keyword == "" or keyword not in manifest:
            print ("-------------------------------")
            print ("-- ApplyPayloads Valid Lists --")
            print ("-------------------------------")
            for i in range(len(manifest)):
                if manifest[i].strip() == "":
                    continue
                print ("@ApplyPayloads(\"%s\")"%(manifest[i]))
            print ("-------------------------------")
            raise Exception("ApplyPayloads could not find '%s.pay'"%(keyword))
        
    if IS_BURP:
        inargs = []
        for keyword in keywords:
            stream = burp.RequestEngine.getResourceAsStream("/Lib/haptyc/PayloadStrings/"+keyword+".pay")
            inargs += [GetDataFromStream(stream).split("\n")]
        return ApplyList(*inargs)
    else:
        inargs = []
        for keyword in keywords:
            inargs += [os.path.dirname(manifestFile)+"/"+keyword+".pay"]
        return ApplyFilelist(*inargs)

