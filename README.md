# shellbug
Basic command line, text-based, shellcode debugger using [Capstone](http://capstone-engine.org)/[Unicorn](http://unicorn-engine.org).

Wanted to put together a small tool for stepping forward and backwards through basic shellcode interactively. Nothing special but sometimes it's a good learning experience to reinvent the wheel. Obviously it won't work on shellcode with external depedencies (eg API's) but if I find myself using it more than I'll probably go back and build in some API emulation.

May switch it to Curses as well so people don't have seizures if they actually use it ;)

*WARNING* YOU ARE RUNNING SHELLCODE SO KNOW WHAT YOU ARE RUNNING OR RUN IT IN A SAFE ENVIRONMENT *ENDOBLIGATORYDONTBESTUPIDWARNING*

I put this together in a night so it has almost no error handling and probably riddled with bugs. Enjoy!

[![asciicast](https://asciinema.org/a/f5fal4a83ox1wowuzb197hwr2.png)](https://asciinema.org/a/f5fal4a83ox1wowuzb197hwr2)

### Usage

In the program there are only four commands currently.

```
's' = Step forward in execution one instruction
'b' = Step backwards in execution one instruction
'd <address>' = Change memory dump (botton-left) location to specified address
'q' = Quit the program
```

### Change Log

v1.0.1 - 2016OCT06
* Added green color highlighting to dump bytes and registers. Highlights when the value has changed since previous state.
* Added re-generating instructions off a new base address for when code jumps into the middle of an instruction.
* Cleaned up some UI elements and code - trying to normalize it.

v1.0.0 - 2016OCT03
* Initial release.

### Test Cases

Place your shellcode on stdin to start the program. The below shellcode is fairly straight forward and decent for testing - it will decode "Hello World".

```
python shellbug.py '\x40\x49\x83\xC6\x41\x68\x48\x65\x6C\x6C\x39\xC8\x74\xF3\x31\xC9\xC7\x06\x2D\x62\x15\x2D\x80\x36\x42\x46\x47\x83\xFF\x04\x7E\xF6\x31\xF6\x83\xC6\x45\xC7\x06\x30\x2E\x26\x00\x58\xA3\x3D\x00\x00\x00\x31\xFF\xEB\xE1'
```

Translates to -

```
inc eax;
dec ecx;
add esi, 0x41;
push 0x6c6c6548;
cmp eax, ecx;
je 1;
xor ecx, ecx;
mov dword ptr [esi], 0x2d15622d;
xor byte ptr ds:[esi], 0x42;
inc esi;
inc edi;
cmp edi, 4;
jle 22;
xor esi, esi;
add esi, 0x45;
mov dword ptr [esi], 0x00262e30;
pop eax;
mov dword ptr [0x3D], eax; 
xor edi, edi;
jmp 22;
```

This code will show jumping into off-based instructions.

[![asciicast](https://asciinema.org/a/bnjkksthhf3d8utfsaelekfjm.png)](https://asciinema.org/a/bnjkksthhf3d8utfsaelekfjm)

```
python shellbug.py '\x83\xC0\x04\x50\xB9\x1F\x00\x00\x00\xC7\x01\x00\xE8\xFF\x00\x83\xC1\x03\xC7\x01\xE0\xEB\x80\x00\xEB\x07'
```

Translates to -

```
add eax, 4;
push eax;
mov ecx, 0x000001F;
mov dword ptr [ecx], 0xffe800;
add ecx, 3;
mov dword ptr [ecx], 0x80ebe0;
jmp 0x21;
```

