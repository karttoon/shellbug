#!/usr/bin/env python
from capstone import *
from unicorn import *
from unicorn.x86_const import *
import subprocess as sp
import sys

__author__  = "Jeff White [karttoon]"
__email__   = "karttoon@gmail.com"
__version__ = "1.0.0"
__date__    = "03OCT2016"

def get_assembly(SC):

    INSTRUCTIONS = []

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for i in md.disasm(SC, 0x1000000):
        INSTRUCTIONS.append("%x: %-12s %s %s" % (i.address, ("".join([hex(x) for x in i.bytes])).replace("0x",""), i.mnemonic, i.op_str))

    return INSTRUCTIONS

def get_print_ins(mu, SCOUNT, INSTRUCTIONS):
    for INDEX, INS in enumerate(INSTRUCTIONS):
        if SCOUNT == 0:
            EIP = "1000000"
        else:
            EIP = "%x" % mu.reg_read(UC_X86_REG_EIP)
        if EIP in INS:
            EIP = INDEX
            break
        else:
            EIP = len(INSTRUCTIONS)

    if EIP >= 6:
        P_INS.append(INSTRUCTIONS[INDEX - 6])
    else:
        P_INS.append("")

    if EIP >= 5:
        P_INS.append(INSTRUCTIONS[INDEX - 5])
    else:
        P_INS.append("")

    if EIP >= 4:
        P_INS.append(INSTRUCTIONS[INDEX - 4])
    else:
        P_INS.append("")

    if EIP >= 3:
        P_INS.append(INSTRUCTIONS[INDEX - 3])
    else:
        P_INS.append("")

    if EIP >= 2:
        P_INS.append(INSTRUCTIONS[INDEX - 2])
    else:
        P_INS.append("")

    if EIP >= 1:
        P_INS.append(INSTRUCTIONS[INDEX - 1])
    else:
        P_INS.append("")

    #### EIP
    P_INS.append(INSTRUCTIONS[INDEX])
    ####
    print EIP
    print len(INSTRUCTIONS)
    if EIP + 1 < len(INSTRUCTIONS):
        P_INS.append(INSTRUCTIONS[INDEX + 1])
    else:
        P_INS.append("")

    if EIP + 2 < len(INSTRUCTIONS):
        P_INS.append(INSTRUCTIONS[INDEX + 2])
    else:
        P_INS.append("")

    if EIP + 3 < len(INSTRUCTIONS):
        P_INS.append(INSTRUCTIONS[INDEX + 3])
    else:
        P_INS.append("")

    if EIP + 4 < len(INSTRUCTIONS):
        P_INS.append(INSTRUCTIONS[INDEX + 4])
    else:
        P_INS.append("")

    if EIP + 5 < len(INSTRUCTIONS):
        P_INS.append(INSTRUCTIONS[INDEX + 5])
    else:
        P_INS.append("")

    if EIP + 6 < len(INSTRUCTIONS):
        P_INS.append(INSTRUCTIONS[INDEX + 6])
    else:
        P_INS.append("")

    return P_INS

def get_stack(mu, SCOUNT):

    STACK = []

    if SCOUNT > 0:
        STACK_ADDRESS = mu.reg_read(UC_X86_REG_ESP)
    else:
        STACK_ADDRESS = 0x1300000

    STACK_ADDRESS = STACK_ADDRESS - 12 # Step back 3

    for i in range(0,8):
        PRINT_STACK = STACK_ADDRESS + (i*4)
        BYTES = ("".join([("%.2X" % x) for x in mu.mem_read(PRINT_STACK, 4)])).replace("0x", "")
        BYTES = "".join([BYTES[i:i+2] for i in range(0,len(BYTES), 2)][::-1])
        STACK.append("%x: %s" % (PRINT_STACK, BYTES))

    return STACK

def get_dump(mu, SCOUNT, DUMP_ADDRESS, MESSAGE):

    DUMP = []

    try:
        for i in range(0,8):
            BYTES = (" ".join([("%.2X" % x) for x in mu.mem_read(DUMP_ADDRESS + (i*8), 8)])).replace("0x", "")
            ASCII = ""
            for x in mu.mem_read(DUMP_ADDRESS + (i*8), 8):
                if x >= 33 and x <= 126:
                    ASCII += chr(x)
                else:
                    ASCII += "."
            DUMP.append("%x: %s | %s" % (DUMP_ADDRESS + (i*8), BYTES, ASCII))

    except:
        for i in range(0,8):
            DUMP.append("")
        MESSAGE = "ERROR - Unable to dump specified region of memory!"

    return DUMP, MESSAGE

def get_flags(mu, SCOUNT):

    FLAGS = []

    FLAGS = [x for x in "{:016b}".format(mu.reg_read(UC_X86_REG_EFLAGS))]

    return FLAGS

def print_console(mu, MESSAGE, P_INS, DUMP, STACK, FLAGS):
    tmp = sp.call('clear', shell=True)
    print "+" + "-" * 58 + "+" + "-" * 16 + "+"
    print "|   %-54s | EAX: %-8x %1s|" % (P_INS[0], mu.reg_read(UC_X86_REG_EAX), "")
    print "|   %-54s | ECX: %-8x %1s|" % (P_INS[1], mu.reg_read(UC_X86_REG_ECX), "")
    print "|   %-54s | EDX: %-8x %1s|" % (P_INS[2], mu.reg_read(UC_X86_REG_EDX), "")
    print "|   %-54s | EBX: %-8x %1s|" % (P_INS[3], mu.reg_read(UC_X86_REG_EBX), "")
    print "|   %-54s | ESP: %-8x %1s|" % (P_INS[4], mu.reg_read(UC_X86_REG_ESP), "")
    print "|   %-54s | EBP: %-8x %1s|" % (P_INS[5], mu.reg_read(UC_X86_REG_EBP), "")
    print "|\x1b[6;1;37;41m >>%-54s \x1b[0m| ESI: %-8x %1s|" % (P_INS[6], mu.reg_read(UC_X86_REG_ESI), "")
    print "|   %-54s | EDI: %-8x %1s|" % (P_INS[7], mu.reg_read(UC_X86_REG_EDI), "")
    print "|   %-54s | EIP: %-8x %1s|" % (P_INS[8], mu.reg_read(UC_X86_REG_EIP), "")
    print "|   %-54s | C: %s S: %s %5s|" % (P_INS[9], FLAGS[-1], FLAGS[-8], "")
    print "|   %-54s | P: %s T: %s %5s|" % (P_INS[10], FLAGS[-3], FLAGS[-9], "")
    print "|   %-54s | A: %s D: %s %5s|" % (P_INS[11], FLAGS[-5], FLAGS[-11], "")
    print "|   %-54s | Z: %s O: %s %5s|" % (P_INS[12], FLAGS[-7], FLAGS[-12], "")
    print "+" + "-" * 75 + "+"
    print "| %-72s %1s|" % (MESSAGE, "")
    print "+" + "-" * 75 + "+"
    print "|  %-49s |   %-19s|" % (DUMP[0], STACK[0])
    print "|  %-49s |   %-19s|" % (DUMP[1], STACK[1])
    print "|  %-49s |   %-19s|" % (DUMP[2], STACK[2])
    print "|  %-49s |\x1b[6;1;37;41m >>%-19s\x1b[0m|" % (DUMP[3], STACK[3])
    print "|  %-49s |   %-19s|" % (DUMP[4], STACK[4])
    print "|  %-49s |   %-19s|" % (DUMP[5], STACK[5])
    print "|  %-49s |   %-19s|" % (DUMP[6], STACK[6])
    print "|  %-49s |   %-19s|" % (DUMP[7], STACK[7])
    print "+" + "-" * 75 + "+"

def run_sc(SC, SCOUNT, STACK_ADDRESS):

    # Build final code to emulate
    X86_CODE32 = SC

    # Setup values
    mu.reg_write(UC_X86_REG_EAX, 0)
    mu.reg_write(UC_X86_REG_ECX, 0)
    mu.reg_write(UC_X86_REG_EDX, 0)
    mu.reg_write(UC_X86_REG_EBX, 0)
    mu.reg_write(UC_X86_REG_EBP, 0)
    mu.reg_write(UC_X86_REG_ESI, 0)
    mu.reg_write(UC_X86_REG_EDI, 0)
    mu.mem_write(0x1000000, "\x00" * 4 * 1024 * 1024)

    # Write code to memory
    mu.mem_write(ADDRESS, X86_CODE32)

    # Initialize Stack for functions
    mu.reg_write(UC_X86_REG_ESP, STACK_ADDRESS)

    # Run the code
    try:
        mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32), 0, SCOUNT)
    except UcError as e:
        print "Error: %s" % e

    return mu

# Get shellcode from command line
SC = sys.argv[1]
SC = sys.argv[1].replace("\\x", "")
SC = SC.replace("0x", "")
SC = [SC[x:x + 2] for x in range(0, len(SC), 2)]
SC = "".join([chr(int(x, 16)) for x in SC])

# Test SC
'''
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
jmp 25;'
'''
#SC = b'\x40\x49\x81\xC6\x41\x00\x00\x01\x68\x48\x65\x6C\x6C\x39\xC8\x74\xF0\x31\xC9\xC7\x06\x2D\x62\x15\x2D\x80\x36\x42\x46\x47\x83\xFF\x04\x7E\xF6\x31\xF6\x81\xC6\x45\x00\x00\x01\xC7\x06\x30\x2E\x26\x00\x58\xA3\x3D\x00\x00\x01\x31\xFF\xEB\xDE'

ADDRESS = 0x1000000
mu = Uc(UC_ARCH_X86, UC_MODE_32)

# Initialize memory
mu.mem_map(ADDRESS, 4 * 1024 * 1024)

SCOUNT = 0

INSTRUCTIONS = get_assembly(SC)

LAST_COMMAND = ""
MESSAGE = ""

while True:

    # Run code
    if SCOUNT > 0:
        mu = run_sc(SC, SCOUNT, STACK_ADDRESS)
    else:
        DUMP_ADDRESS = 0x1000000
        STACK_ADDRESS = 0x1300000
        mu.reg_write(UC_X86_REG_EIP, 0x1000000)
        mu.reg_write(UC_X86_REG_ESP, 0x1300000)

    # Build instructions for print
    P_INS = []
    P_INS = get_print_ins(mu, SCOUNT, INSTRUCTIONS)

    # Grab stack for print
    STACK = []
    STACK = get_stack(mu, SCOUNT)

    # Grab dump for print
    DUMP = []
    DUMP, MESSAGE = get_dump(mu, SCOUNT, DUMP_ADDRESS, MESSAGE)

    # Grab flags for print
    FLAGS = []
    FLAGS = get_flags(mu, SCOUNT)

    # Print the console
    print_console(mu, MESSAGE, P_INS, DUMP, STACK, FLAGS)

    if LAST_COMMAND == "":
        COMMAND = raw_input("#[ ]> ")
    else:
        COMMAND = raw_input("#[%s]> " % LAST_COMMAND)

    if COMMAND == "":
        COMMAND = LAST_COMMAND

    # Step forward
    if COMMAND.lower() == "s":
        SCOUNT += 1
        LAST_COMMAND = "s"

    # Step backward
    if COMMAND.lower() == "b":
        SCOUNT -= 1
        LAST_COMMAND = "b"

    # Print commands
    if COMMAND == "?":
        MESSAGE = "(b)ack | (s)tep | (q)uit | (d)ump <ADDRESS>"
    else:
        MESSAGE = ""

    # Get dump address
    if (COMMAND.lower()).startswith("d "):
        DUMP_ADDRESS = int(COMMAND.split(" ")[1].replace("0x", ""), 16)
    if COMMAND.lower() == "q":
        sys.exit(1)