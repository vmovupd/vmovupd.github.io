---
title: Microcorruption Notes
author: vmovupd
date: 2025-01-07 18:00:00 +0000
categories: [Blog, Embedded Security]
tags: [microcorruption]
description: My (micro)solutions for Microcorruption CTF
render_with_liquid: false
---

<style>body {text-align: justify}</style>

The description of the CTF is [**here**](https://microcorruption.com/about). The manual that has basic introduction to MSP430 assembly and interrupts for LockIT Pro is [**here**](https://microcorruption.com/public/manual.pdf). Instruction set description is available [**here**](https://www.ti.com/sc/docs/products/micro/msp430/userguid/ag_b.pdf).

## Tutorial

In Tutorial level (which seems to be located in Chicago according to the map), the function `check_password` checks if the password length is 8 character (9 characters including null byte for EOL) and sets the flag (`r15`) if the check was sucessfully passed.
```assembly
4484 <check_password>
4484:  6e4f           mov.b	@r15, r14 ; r15 holds the address containing the password provided by the user, r14 holds the value
4486:  1f53           inc	r15
4488:  1c53           inc	r12 ; counter for password length
448a:  0e93           tst	r14 ; check if the value is null byte to determine the end of string
448c:  fb23           jnz	$-0x8 <check_password+0x0> ; loop
448e:  3c90 0900      cmp	#0x9, r12 ; check if the password length is 8 bytes
4492:  0224           jz	$+0x6 <check_password+0x14> ; jump to set a flag to open the door
4494:  0f43           clr	r15
4496:  3041           ret
4498:  1f43           mov	#0x1, r15
449a:  3041           ret
```

## New Orleans

The function `check_password` checks if the password is the one that is stored in memory at the address `0x2400`.
```assembly
44bc <check_password>
44bc:  0e43           clr	r14 ; set r14 to 0
44be:  0d4f           mov	r15, r13 ; r13 and r15 hold the address containing the password provided by the user
44c0:  0d5e           add	r14, r13 ; r14 is the counter which defines the current position for the character to compare
44c2:  ee9d 0024      cmp.b	@r13, 0x2400(r14) ; compare the corresponding characters
44c6:  0520           jnz	$+0xc <check_password+0x16> ; if the characters are not the same, exit
44c8:  1e53           inc	r14
44ca:  3e92           cmp	#0x8, r14 ; length of the password, including null byte for EOL
44cc:  f823           jnz	$-0xe <check_password+0x2>
44ce:  1f43           mov	#0x1, r15
44d0:  3041           ret
44d2:  0f43           clr	r15
44d4:  3041           ret
```

Live memory dump of the address:
```2400: 605c 2559 6259 7300 0000 0000 0000 0000   `\%YbYs.........```

## Sydney

The password is hardcoded in the `check_password` function instructions as the bytes are compared directly. One has to consider the endiannes as MSP430 is little endian and check that the input is hex encoded. The password is `542c4f545a465a4f`.
```assembly
448a <check_password>
448a:  bf90 542c 0000 cmp	#0x2c54, 0x0(r15) ; r15 holds the password provided by the user
4490:  0d20           jnz	$+0x1c <check_password+0x22>
4492:  bf90 4f54 0200 cmp	#0x544f, 0x2(r15)
4498:  0920           jnz	$+0x14 <check_password+0x22>
449a:  bf90 5a46 0400 cmp	#0x465a, 0x4(r15)
44a0:  0520           jnz	$+0xc <check_password+0x22>
44a2:  1e43           mov	#0x1, r14 ; set the flag
44a4:  bf90 5a4f 0600 cmp	#0x4f5a, 0x6(r15)
44aa:  0124           jz	$+0x4 <check_password+0x24>
44ac:  0e43           clr	r14
44ae:  0f4e           mov	r14, r15
44b0:  3041           ret
```

## Hanoi

First lock with HSM, module 1. The program informs the user that the password shall be between 8 and 16 characters. `test_password_valid` function performs an interrupt (`0x7d`) to test whether the password provided by the user (stored at `0x2400`, passed as `r15`) is correct and if so, set a flag at `0x43f8`, passed as `r14`; the flag is written to `r15` at the end of the function. In the `login` function, however, the door is unlocked based on the value at the address `0x2410` (the value is controlled by the attacker as there is no bounds checking, even though the program specifies required password length) which shall be `0x31` (1 in ASCII). `r15` is only used to determine whether or not the value at `0x2410` shall be overwritten with `a8` which would effectively **prevent the user from unlocking the door, if the password is correct**.

```assembly
4520 <login>
...
4544:  b012 5444      call	#0x4454 <test_password_valid>
4548:  0f93           tst	r15 ; flag set by HSM
454a:  0324           jz	$+0x8 <login+0x32>
454c:  f240 a800 1024 mov.b	#0xa8, &0x2410 ; if the password is correct, prevent user from unlocking the door by setting 0x2410 to random value?
4552:  3f40 d344      mov	#0x44d3 "Testing if password is valid.", r15
4556:  b012 de45      call	#0x45de <puts>
455a:  f290 3100 1024 cmp.b	#0x31, &0x2410 ; check if the 17th byte in password provided is 1
4560:  0720           jnz	$+0x10 <login+0x50>
4562:  3f40 f144      mov	#0x44f1 "Access granted.", r15
4566:  b012 de45      call	#0x45de <puts>
456a:  b012 4844      call	#0x4448 <unlock_door>
456e:  3041           ret
4570:  3f40 0145      mov	#0x4501 "That password is not correct.", r15
4574:  b012 de45      call	#0x45de <puts>
4578:  3041           ret
```

So to get the door unlocked, input shall override 17th byte (`0x2410`) to 1 (`0x31`).

## Cusco

This is the second version of the lock from Hanoi, the changelog states `fixed issues with passwords which may be too long`. The password is written on the stack and stack pointer points to the password after it has been entered. At the end of the `login` function, the program adds 16 bytes to the stack pointer and returns to the address pointed by the stack pointer:
```assembly
4500 <login>
...
453a:  3150 1000      add	#0x10, sp
453e:  3041           ret
```
As there is no ASLR or stack canary, it is possible to *redirect program counter using stack buffer overflow*. The program shall execute `unlock_door` function that is located at `0x4446` after the return instruction. The answer is `414141414141414141414141414141414644`.

The stack to visualize the exploitation: 
```
43e0: 5645 0300 ca45 0000 0a00 0000 3a45 4141   VE...E......:EAA ; SP points to 43ee (41)
43f0: 4141 4141 4141 4141 4141 4141 4141 4644   AAAAAAAAAAAAAAFD ; After add is executed, it points to 4446
4400: 0040 0044 1542 5c01 75f3 35d0 085a 3f40   .@.D.B\.u.5..Z?@
```

## Reykjavik

There is no HSM, but `developers have implemented military-grade on-device encryption to keep the password secure`. Before `main` is called, function `__do_copy_data` copies `0x7c` bytes from `0x4538` to `0x2400`. The data block contains the following bytes that are not valid instructions:
```
4c85 1bc5 80df e9bf 3864 2bc6 4277 62b8
c3ca d965 a40a c1a3 bbd1 a6ea b3eb 180f
78af ea7e 5c8e c695 cb6f b8e9 333c 5aa1
5cee 906b d1aa a1c3 a986 8d14 08a5 a22c
baa5 1957 192d abe1 66b9 7d38 4a08 e95c
d919 8069 07a5 ef01 caa2 a30d f344 815e
3e10 e765 2bc8 2837 abad ab3f 8cfa 754d
8ff0 b083 6b3e b3c7 aefe b409
```

`main` calls `enc` function passing the address `0x2400` (which currently holds the encrypted data) and `0xf8` (the size of encrypted data doubled) that is followed by calling whatever is at `0x2400`. `enc` contains RC4 algorithm which can be recognized by looking at the flow: two loops that iterate 256 times (Key Scheduling Algorithm); one more loop containing PRGA and XOR (Figure 1). `enc` will decrypt the data in-place that has been passed to it. The algorithm is modified to permit keys up to 16 bytes (see `and 0xf, r10` on the screenshot).

![RC4 algorithm in MSP430 from the level](/assets/img/microcorruption_rc4.png)
_Figure 1: Screenshot of Cutter with RC4 algorithm explained from the level_

The bytes located at `0x4472` contain the string `ThisIsSecureRight?`, however, as the algorithms limits key length to 16 bytes, the actual key is `ThisIsSecureRigh`. The data block can be decrypted:
* [CyberChef](https://cyberchef.org/#recipe=RC4(%7B'option':'UTF8','string':'ThisIsSecureRigh'%7D,'Hex','Hex')&input=NGM4NTFiYzU4MGRmZTliZjM4NjQyYmM2NDI3NzYyYjhjM2NhZDk2NWE0MGFjMWEzYmJkMWE2ZWFiM2ViMTgwZjc4YWZlYTdlNWM4ZWM2OTVjYjZmYjhlOTMzM2M1YWExNWNlZTkwNmJkMWFhYTFjM2E5ODY4ZDE0MDhhNWEyMmNiYWE1MTk1NzE5MmRhYmUxNjZiOTdkMzg0YTA4ZTk1Y2Q5MTk4MDY5MDdhNWVmMDFjYWEyYTMwZGYzNDQ4MTVlM2UxMGU3NjUyYmM4MjgzN2FiYWRhYjNmOGNmYTc1NGQ4ZmYwYjA4MzZiM2ViM2M3YWVmZWI0MDk)
* using python:
```python
from arc4 import ARC4
rc4 = ARC4(b"ThisIsSecureRigh")
ciphertext = bytes.fromhex("4c851bc580dfe9bf38642bc6427762b8c3cad965a40ac1a3bbd1a6eab3eb180f78afea7e5c8ec695cb6fb8e9333c5aa15cee906bd1aaa1c3a9868d1408a5a22cbaa51957192dabe166b97d384a08e95cd919806907a5ef01caa2a30df344815e3e10e7652bc82837abadab3f8cfa754d8ff0b0836b3eb3c7aefeb409")
rc4.decrypt(ciphertext)
```
* simply putting a breakpoint on the call to `0x2400` in `main`. 

Then, using the disassembler, view the code:

![Login function from the level](/assets/img/microcorruption_login.png)
_Figure 2. Screenshot of Cutter with login function from the level_

It prints the message `what's the password?` (stored at `0x4520`) and asks the user to input the password. After that, it compares the first two bytes with the hardcoded values. Considering the endiannes, the solution will be any password that starts with `1ad6` (hex encoded). 

The reason for having `0xf8` as the size of encrypted data and not `0x7c` (true encrypted data block size) may be to overwrite the key stream or confuse the attacker.

## Whitehorse

The lock is attached to HSM, module 2. **The main difference between HSM module 1 and HSM module 2** is that the first one only checks the password and sets the flag in memory, while second checks the password and sends an interrupt to unlock the door. Essentialy, this is an upgraded version of the lock from Cusco level. `main` contains only a call to `conditional_unlock_door`; there is no `unlock_door` function in the program at all. Thus, shellcode written on the stack which would replicate the `unlock_door` functionality is required to unlock the door. The shellcode will be executed using using the same technique from Cusco.

The simplest shellcode looks like this (`30127f00b0123245` in bytes):
```assembly
push    #0x7f ; 0x7f is an interrupt to unlock the door according to the manual
call    #0x4532 <INT>
```
The password is written to `0x3088` and the return address is stored at `0x3098`. There is no need to worry about the size of the shellcode as `0x30` is passed to `getsn` function, meaning the shellcode size can be not more than 46 bytes (2 bytes are taken by the return address). It is possible to execute shellcode after (the return address will point to `0x309a`) or before the return address (the return address will point to `0x3088`) as there is enough space for both approaches (the amount of CPU cycles is the same):
* After: `313131313131313131313131313131319a3030127f00b0123245`
* Before: `30127f00b012324531313131313131318830`

## Offtop
Baku is located in Kyrgystan on the map.