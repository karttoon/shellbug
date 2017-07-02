#!/usr/bin/env python
from capstone import *
from unicorn import *
from unicorn.x86_const import *
import subprocess as sp
import sys

__author__  = "Jeff White [karttoon] @noottrak"
__email__   = "karttoon@gmail.com"
__version__ = "1.0.1"
__date__    = "06OCT2016"

def get_dumpbytes(SC):

    # Create initial byte list - used for comparison to identify modified bytes
    DUMP_LIST = []

    for i in SC:
        DUMP_LIST.append("%.2X" % ord(i))
    for i in range(0,128):
        DUMP_LIST.append("00")

    return DUMP_LIST

def get_instructions(mu, SC, SCOUNT):

    # Create instruction list
    INSTRUCTIONS = []

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    FOUND = 0

    if SCOUNT == 0:
        for i in md.disasm(SC, 0):
            INSTRUCTIONS.append("%.8X: %-12s %s %s" % (i.address,
                                                       (("".join([hex(x) for x in i.bytes])).replace("0x","")).upper(),
                                                       i.mnemonic,
                                                       i.op_str))
    else:
        for i in md.disasm(str(mu.mem_read(0, len(SC) * 2)), 0):
            INSTRUCTIONS.append("%.8X: %-12s %s %s" % (i.address,
                                                       (("".join([hex(x) for x in i.bytes])).replace("0x","")).upper(),
                                                       i.mnemonic,
                                                       i.op_str))

        # Validate EIP will be an disassembled instruction, otherwise disassemble again with EIP as OEP
        for i in INSTRUCTIONS:
            if "%.8X" % mu.reg_read(UC_X86_REG_EIP) in i:
                FOUND = 1
        if FOUND == 0:
            INSTRUCTIONS = []
            EIP = mu.reg_read(UC_X86_REG_EIP)

            # Offset by EIP to keep the correct addresses
            for i in md.disasm(str(mu.mem_read(EIP, len(SC) * 2)), 0):
                INSTRUCTIONS.append("%.8X: %-12s %s %s" % ((i.address + EIP - 0),
                                                           (("".join(["%.2X" % x for x in i.bytes])).replace("0x", "")).upper(),
                                                           i.mnemonic,
                                                           i.op_str))

    return INSTRUCTIONS

def get_print_ins(mu, SCOUNT, INSTRUCTIONS):

    for INDEX, INS in enumerate(INSTRUCTIONS):
        if SCOUNT == 0:
            EIP = "00000000"
        else:
            EIP = "%.8X" % mu.reg_read(UC_X86_REG_EIP)
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
        STACK_ADDRESS = 0x0300000

    STACK_ADDRESS = STACK_ADDRESS - 12 # Step back 3

    for i in range(0,8):
        PRINT_STACK = STACK_ADDRESS + (i*4)
        BYTES = ("".join([("%.2X" % x) for x in mu.mem_read(PRINT_STACK, 4)])).replace("0x", "")
        BYTES = "".join([BYTES[i:i+2] for i in range(0,len(BYTES), 2)][::-1])
        STACK.append("%.8X: %s" % (PRINT_STACK, BYTES))

    return STACK

def get_registers(mu, SCOUNT, REGISTER_LIST):

    OLD_REGISTERS = REGISTER_LIST
    REGISTER_LIST = []

    REGISTER_LIST.append(mu.reg_read(UC_X86_REG_EAX))
    REGISTER_LIST.append(mu.reg_read(UC_X86_REG_ECX))
    REGISTER_LIST.append(mu.reg_read(UC_X86_REG_EDX))
    REGISTER_LIST.append(mu.reg_read(UC_X86_REG_EBX))
    REGISTER_LIST.append(mu.reg_read(UC_X86_REG_ESP))
    REGISTER_LIST.append(mu.reg_read(UC_X86_REG_EBP))
    REGISTER_LIST.append(mu.reg_read(UC_X86_REG_ESI))
    REGISTER_LIST.append(mu.reg_read(UC_X86_REG_EDI))

    REGISTERS =[]

    for INDEX,VALUE in enumerate(REGISTER_LIST):
        if VALUE != OLD_REGISTERS[INDEX]:
            REGISTERS.append("\x1b[6;30;42m" + "%.8X" % VALUE + "\x1b[0m")
        else:
            REGISTERS.append("%.8X" % VALUE)

    return REGISTERS, REGISTER_LIST


def get_dump(mu, SCOUNT, DUMP_ADDRESS, MESSAGE):

    DUMP_LIST = []
    VALUE_LIST = []

    # Color bytes which have changed since original
    if SCOUNT > 0:
        DUMP_LIST = ["%.2X" % x for x in mu.mem_read(DUMP_ADDRESS, 64)]
    else:
        for i in range(0,64):
            DUMP_LIST.append("00")

    for INDEX, VALUE in enumerate(DUMP_LIST):
        if VALUE != ORIGINAL_BYTES[INDEX + (DUMP_ADDRESS - 0)]:
            VALUE_LIST.append("\x1b[6;30;42m" + VALUE + "\x1b[0m")
        else:
            VALUE_LIST.append("%s" % VALUE)

    DUMP = []

    # Setup the initial dump view with the bytes from the shellcode
    if SCOUNT == 0 and DUMP_ADDRESS == 0:
        for i in range(0,8):
            BYTES = " ".join(ORIGINAL_BYTES[i*8:(i*8)+8])
            ASCII = ""
            for x in ORIGINAL_BYTES[i*8:(i*8)+8]:
                x = int(x, 16)
                if x >= 33 and x <= 126:
                    ASCII += chr(x)
                else:
                    ASCII += "."
            DUMP.append("%.8X: %s | %s" % (DUMP_ADDRESS + (i*8), BYTES, ASCII))
    else:
        try:
            for i in range(0,8):
                BYTES = " ".join(VALUE_LIST[i*8:(i*8)+8])
                ASCII = ""
                for x in mu.mem_read(DUMP_ADDRESS + (i*8), 8):
                    if x >= 33 and x <= 126:
                        ASCII += chr(x)
                    else:
                        ASCII += "."
                DUMP.append("%.8X: %s | %s" % (DUMP_ADDRESS + (i*8), BYTES, ASCII))
        except:
            for i in range(0,8):
                DUMP.append("")
            MESSAGE = "ERROR - Unable to dump specified region of memory!"

    return DUMP, MESSAGE

def get_registers(mu, SCOUNT, REGISTER_LIST):

    OLD_REGISTERS = REGISTER_LIST
    REGISTER_LIST = []

    REGISTER_LIST.append(mu.reg_read(UC_X86_REG_EAX))
    REGISTER_LIST.append(mu.reg_read(UC_X86_REG_ECX))
    REGISTER_LIST.append(mu.reg_read(UC_X86_REG_EDX))
    REGISTER_LIST.append(mu.reg_read(UC_X86_REG_EBX))
    REGISTER_LIST.append(mu.reg_read(UC_X86_REG_ESP))
    REGISTER_LIST.append(mu.reg_read(UC_X86_REG_EBP))
    REGISTER_LIST.append(mu.reg_read(UC_X86_REG_ESI))
    REGISTER_LIST.append(mu.reg_read(UC_X86_REG_EDI))

    REGISTERS =[]

    for INDEX,VALUE in enumerate(REGISTER_LIST):
        if VALUE != OLD_REGISTERS[INDEX]:
            REGISTERS.append("\x1b[6;30;42m" + "%.8X" % VALUE + "\x1b[0m")
        else:
            REGISTERS.append("%.8X" % VALUE)

    return REGISTERS, REGISTER_LIST

def get_flags(mu, SCOUNT, FLAG_LIST):

    OLD_FLAGS = FLAG_LIST
    FLAG_LIST = [x for x in "{:016b}".format(mu.reg_read(UC_X86_REG_EFLAGS))]

    FLAGS = []

    for INDEX, VALUE in enumerate(FLAG_LIST):
        if VALUE != OLD_FLAGS[INDEX]:
            FLAGS.append("\x1b[6;30;42m" + VALUE + "\x1b[0m")
        else:
            FLAGS.append(VALUE)

    return FLAGS, FLAG_LIST


def print_console(mu, MESSAGE, P_INS, DUMP, STACK, FLAGS, REGISTERS):
    tmp = sp.call('clear', shell=True)
    print "+" + "-" * 62 + "+" + "-" * 16 + "+"
    print "|   %-58s | EAX: %-8s %1s|" % (P_INS[0], REGISTERS[0], "") # EAX
    print "|   %-58s | ECX: %-8s %1s|" % (P_INS[1], REGISTERS[1], "") # ECX
    print "|   %-58s | EDX: %-8s %1s|" % (P_INS[2], REGISTERS[2], "") # EDX
    print "|   %-58s | EBX: %-8s %1s|" % (P_INS[3], REGISTERS[3], "") # EBX
    print "|   %-58s | ESP: %-8s %1s|" % (P_INS[4], REGISTERS[4], "") # ESP
    print "|   %-58s | EBP: %-8s %1s|" % (P_INS[5], REGISTERS[5], "") # EBP
    print "|\x1b[6;1;37;41m >>%-58s \x1b[0m| ESI: %-8s %1s|" % (P_INS[6], REGISTERS[6], "") # ESI
    print "|   %-58s | EDI: %-8s %1s|" % (P_INS[7], REGISTERS[7], "") # EDI
    print "|   %-58s | EIP: %.8X %1s|" % (P_INS[8], mu.reg_read(UC_X86_REG_EIP), "")
    print "|   %-58s | C: %s S: %s %5s|" % (P_INS[9], FLAGS[-1], FLAGS[-8], "")
    print "|   %-58s | P: %s T: %s %5s|" % (P_INS[10], FLAGS[-3], FLAGS[-9], "")
    print "|   %-58s | A: %s D: %s %5s|" % (P_INS[11], FLAGS[-5], FLAGS[-11], "")
    print "|   %-58s | Z: %s O: %s %5s|" % (P_INS[12], FLAGS[-7], FLAGS[-12], "")
    print "+" + "-" * 79 + "+"
    print "| %-76s %1s|" % (MESSAGE, "")
    print "+" + "-" * 79 + "+"
    print "|   %s %8s|   %-19s|" % (DUMP[0], "", STACK[0])
    print "|   %s %8s|   %-19s|" % (DUMP[1], "", STACK[1])
    print "|   %s %8s|   %-19s|" % (DUMP[2], "", STACK[2])
    print "|   %s %8s|\x1b[6;1;37;41m >>%-19s\x1b[0m|" % (DUMP[3], "", STACK[3])
    print "|   %s %8s|   %-19s|" % (DUMP[4], "", STACK[4])
    print "|   %s %8s|   %-19s|" % (DUMP[5], "", STACK[5])
    print "|   %s %8s|   %-19s|" % (DUMP[6], "", STACK[6])
    print "|   %s %8s|   %-19s|" % (DUMP[7], "", STACK[7])
    print "+" + "-" * 79 + "+"

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
    mu.mem_write(0, "\x00" * 4 * 1024 * 1024)

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
SC = SC.replace("'", "")
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

ADDRESS = 0
mu = Uc(UC_ARCH_X86, UC_MODE_32)

# Initialize memory and some program values
mu.mem_map(ADDRESS, 4 * 1024 * 1024)

SCOUNT = 0
LAST_COMMAND = ""
MESSAGE = ""
DUMP = []
STACK = []

ORIGINAL_BYTES = get_dumpbytes(SC)
INSTRUCTIONS = get_instructions(mu, SC, SCOUNT)
REGISTER_LIST = [mu.reg_read(UC_X86_REG_EAX),
                 mu.reg_read(UC_X86_REG_ECX),
                 mu.reg_read(UC_X86_REG_EDX),
                 mu.reg_read(UC_X86_REG_EBX),
                 mu.reg_read(UC_X86_REG_ESP),
                 mu.reg_read(UC_X86_REG_EBP),
                 mu.reg_read(UC_X86_REG_ESI),
                 mu.reg_read(UC_X86_REG_EDI)]
FLAG_LIST = [x for x in "{:016b}".format(mu.reg_read(UC_X86_REG_EFLAGS))]

while True:

    # Run code
    if SCOUNT > 0:
        mu = run_sc(SC, SCOUNT, STACK_ADDRESS)
        # Grab instructions again to see if code has changed
        # Won't
        INSTRUCTIONS = get_instructions(mu, SC, SCOUNT)
    else:
        DUMP_ADDRESS = 0
        STACK_ADDRESS = 0x0300000
        mu.reg_write(UC_X86_REG_EAX, 0)
        mu.reg_write(UC_X86_REG_ECX, 0)
        mu.reg_write(UC_X86_REG_EDX, 0)
        mu.reg_write(UC_X86_REG_EBX, 0)
        mu.reg_write(UC_X86_REG_ESP, 0x0300000)
        mu.reg_write(UC_X86_REG_EBP, 0)
        mu.reg_write(UC_X86_REG_ESI, 0)
        mu.reg_write(UC_X86_REG_EDI, 0)
        mu.reg_write(UC_X86_REG_EIP, 0)


    # Build instructions for print
    P_INS = []
    P_INS = get_print_ins(mu, SCOUNT, INSTRUCTIONS)

    # Grab stack for print
    STACK = []
    STACK = get_stack(mu, SCOUNT)

    # Grab dump for print
    DUMP, MESSAGE = get_dump(mu, SCOUNT, DUMP_ADDRESS, MESSAGE)

    # Grab flags for print
    FLAGS, FLAG_LIST = get_flags(mu, SCOUNT, FLAG_LIST)

    # Grab general registers for print
    REGISTERS, REGISTER_LIST = get_registers(mu, SCOUNT, REGISTER_LIST)

    # Print the console
    print_console(mu, MESSAGE, P_INS, DUMP, STACK, FLAGS, REGISTERS)

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

    # Get dump address
    if (COMMAND.lower()).startswith("d "):
        DUMP_ADDRESS = int(COMMAND.split(" ")[1].replace("0x", ""), 16)

    # Print commands
    if COMMAND == "?":
        MESSAGE = "(b)ack | (s)tep | (q)uit | (d)ump <ADDRESS>"
    else:
        MESSAGE = ""

    # Quit
    if COMMAND.lower() == "q":
        sys.exit(1)
