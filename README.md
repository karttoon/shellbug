# shellbug
Basic command line, text-based, shellcode debugger using [Capstone](http://capstone-engine.org)/[Unicorn](http://unicorn-engine.org).

Wanted to put together a small tool for stepping forward and backwards through basic shellcode interactively. Nothing special but sometimes it's a good learning experience to reinvent the wheel. Obviously it won't work on shellcode with external depedencies (eg API's) but if I find myself using it more than I'll probably go back and build in some API emulation.

May switch it to Curses as well so people don't have seizures if they actually use it ;)

*WARNING* YOU ARE RUNNING SHELLCODE SO KNOW WHAT YOU ARE RUNNING OR RUN IT IN A SAFE ENVIRONMENT *ENDOBLIGATORYDONTBESTUPIDWARNING*

I put this together in a night so it has almost no error handling and probably riddled with bugs. Enjoy!

[![asciicast](https://asciinema.org/a/bjrw8ggrxlb54cvl73z8oa62d.png)](https://asciinema.org/a/bjrw8ggrxlb54cvl73z8oa62d)

### Usage

Place your shellcode on stdin to start the program. The below shellcode is fairly straight forward and decent for testing - it will decode "Hello World" basically.

```
python shellbug.py '\x40\x49\x81\xC6\x41\x00\x00\x01\x68\x48\x65\x6C\x6C\x39\xC8\x74\xF0\x31\xC9\xC7\x06\x2D\x62\x15\x2D\x80\x36\x42\x46\x47\x83\xFF\x04\x7E\xF6\x31\xF6\x81\xC6\x45\x00\x00\x01\xC7\x06\x30\x2E\x26\x00\x58\xA3\x3D\x00\x00\x01\x31\xFF\xEB\xDE'
```

Translates to -

```
inc eax;
dec ecx;
add esi, 0x1000041;
push 0x6c6c6548;
cmp eax, ecx;
je 1;
xor ecx, ecx;
mov dword ptr [esi], 0x2d15622d;
xor byte ptr ds:[esi], 0x42;
inc esi;
inc edi;
cmp edi, 4;
jle 25;
xor esi, esi;
add esi, 0x1000045;
mov dword ptr [esi], 0x00262e30;
pop eax;
mov dword ptr [0x100003D], eax; 
xor edi, edi;
jmp 25;
```

In the program there are only four commands currently.

```
's' = Step forward in execution one instruction 
'b' = Step backwards in execution one instruction
'd <address>' = Change memory dump (botton-left) location to specified address
'q' = Quit the program
```

