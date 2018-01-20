#!/usr/bin/env python3

# REQUIRES VASM!

import struct
from subprocess import run, DEVNULL
import tempfile
from collections import namedtuple
import re
from sys import argv

class PEF:
    MAGIC = b'Joy!'
    
    CONT_HEAD_FMT = '>4s4s4s5I2HI'
    CONT_HEAD_LEN = struct.calcsize(CONT_HEAD_FMT)
    
    SEC_HEAD_FMT = '>i5I4B'
    SEC_HED_LEN = struct.calcsize(SEC_HEAD_FMT)

    @classmethod
    def read_from(cls, path):
        with open(path, 'rb') as f:
            return cls(f.read())

    def __init__(self, data):
        (magic, fourcc, arch, ver,
        timestamp, old_def_ver, old_imp_ver, cur_ver,
        sec_count, inst_sec_count, reserv) = struct.unpack_from(self.CONT_HEAD_FMT, data)

        sec_earliest = len(data)
        sec_latest = 0

        self.sections = []
        self.sectypes = []
        self.headeroffsets = []

        self.code = None

        for i in range(sec_count):
            sh_offset = self.CONT_HEAD_LEN + self.SEC_HED_LEN*i

            (sectionName, sectionAddress, execSize,
            initSize, rawSize, containerOffset,
            regionKind, shareKind, alignment, reserved) = struct.unpack_from(self.SEC_HEAD_FMT, data, sh_offset)

            the_sec = data[containerOffset : containerOffset + rawSize]

            if regionKind == 0 and execSize == initSize == rawSize:
                the_sec = bytearray(the_sec)
                self.code = the_sec

            self.sections.append(the_sec)
            self.sectypes.append(regionKind)
            self.headeroffsets.append(sh_offset)

            sec_earliest = min(sec_earliest, containerOffset)
            sec_latest = max(sec_latest, containerOffset + rawSize)

        if sec_latest < len(data):
            print('too short', hex(sec_latest), hex(len(data)))

        self.header = data[:sec_earliest]

    def __bytes__(self):
        accum = bytearray(self.header)

        for i in range(len(self.sections)):
            the_sec = self.sections[i]
            hoff = self.headeroffsets[i]

            while len(accum) % 16:
                accum.append(0)

            new_off = len(accum)
            new_len = len(the_sec)

            accum.extend(the_sec)

            struct.pack_into('>I', accum, hoff + 20, new_off)

            if the_sec is self.code:
                for i in range(8, 20, 4):
                    struct.pack_into('>I', accum, hoff + i, new_len)

        return bytes(accum)

    def write_to(self, path):
        with open(path, 'wb') as f:
            f.write(bytes(self))

def insert_branch(bin, from_offset=None, to_offset=None):
    maxdel = 0x2000000

    if from_offset is None: from_offset = len(bin)
    if to_offset is None: to_offset = len(bin)

    while len(bin) < from_offset + 4:
        bin.append(0)

    if from_offset & 3 or to_offset & 3:
        raise ValueError('not aligned')

    delta = to_offset - from_offset
    
    insn = (18 << 26) | (delta & 0x3FFFFFC)
    struct.pack_into('>I', bin, from_offset, insn)

def clean_code(code):
    """Accept single in, array of bytes, array of long ints, etc"""

    try:
        code.decode
    except AttributeError:
        pass
    else:
        return code

    try:
        iter(code)
    except TypeError:
        code = [code]

    code = list(code)

    if len(code) % 4 == 0 and not any(x > 255 for x in code):
        return bytes(code)

    return b''.join(x.to_bytes(4, byteorder='big') for x in code)

def is_branch(code):
    code = clean_code(code)

    if len(code) != 4:
        raise NotImplementedError('only implemented for single instructions')

    opcode = code[0] >> 2

    return opcode in [16, 18]


def patch(bin, offset, code):
    code = clean_code(code)

    rescued = p.code[offset : offset+4]
    if is_branch(rescued):
        raise NotImplementedError('cannot patch immediately before a branch')

    # patch at the site
    insert_branch(p.code, from_offset=offset, to_offset=len(p.code))

    # and add the new code
    p.code.extend(code)
    p.code.extend(rescued)
    insert_branch(p.code, to_offset=offset+4)

def asm(code):
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write(code)
        input_tmp = f.name
    with tempfile.NamedTemporaryFile() as f:
        output_tmp = f.name

    run(['vasmppc_mot', '-Fbin', '-spaces', '-o', output_tmp, input_tmp], check=True, stdout=DEVNULL)

    with open(output_tmp, 'rb') as f:
        return f.read()

def scan_symbols(bin):
    last_one_ended_at = 0

    for i in range(0, len(bin), 4):
        try:
            guts = struct.unpack_from('>IIIIxB', bin, i)
        except:
            continue

        if guts[0] != 0: continue

        if len(bin) < i + 18 + guts[-1]: continue
        name = bin[i + 18:][:guts[-1]]

        if i - guts[3] < last_one_ended_at: continue
        if guts[3] % 4 != 0: continue

        if not re.match(rb'^\w+$', name): continue

        last_one_ended_at = i + 18 # whatever

        # now interpret properly
        func_start = i - guts[3]
        func_len = guts[3]

        yield func_start, func_len, name.decode('ascii')

def parse_location(locstr, locdict):
    suffix = ''

    if '+' in locstr:
        base, offset = locstr.split('+')
        suffix = '+' + offset
        offset = eval(offset)
    elif '-' in locstr:
        base, offset = locstr.split('-')
        suffix = '-' + offset
        offset = -eval(offset)
    else:
        base = locstr
        offset = 0

    # now need to account for multiple bases!

    funcs = [(x, int(x[2:], 16), None) for x in base.split('/') if x.startswith('0x')]

    regex = '^(' + re.escape(base).replace(r'\/', '|').replace(r'\*', r'.*') + ')$'
    regex = re.compile(regex, flags=re.IGNORECASE)

    for func_name, (func_start, func_len) in locdict.items():
        if regex.match(func_name):
            funcs.append((func_name, func_start, func_len))

    for func_name, func_start, func_len in funcs:
        if offset < 0:
            final = func_start + func_len + offset
        else:
            final = func_start + offset

        yield func_name + suffix, final

MACROS = """
    macro s
    stmw    r0, -128(sp)
    mflr    r0
    stw     r0, -132(sp)
    endm

    macro r
    lwz     r0, -132(sp)
    mtlr    r0
    lmw     r3, -116(sp)
    lwz     r2, -120(sp)
    lwz     r0, -128(sp)
    endm

    MACRO flush
    bl      \\@
    DC.B    "^b"
    DC.B    0
    ALIGN   2
\\@
    mflr    r3
    li      r0, 96
    sc
    ENDM

    MACRO log
    bl      \\@
    DC.B    \\1
    DC.B    0
    ALIGN   2
\\@
    mflr    r3
    li      r0, 96
    sc
    ENDM

    MACRO logln
    bl      \\@
    DC.B    \\1
    DC.B    "^n"
    DC.B    0
    ALIGN   2
\\@
    mflr    r3
    li      r0, 96
    sc
    ENDM

    MACRO logreg
    lwz     r3, \\1*4-128(sp)
    li      r4, 3
    li      r0, 97
    sc
    ENDM


"""

# print(MACROS)

me, src, dest, *cmds = argv

p = PEF.read_from(src)

locdict = {n: (o, l) for (o, l, n) in scan_symbols(p.code)}

cmds = iter(cmds)

for c in cmds:
    c2 = next(cmds)

    for name, offset in parse_location(c, locdict):
        print(name, hex(offset))

        if c2.startswith('nop'):
            for i in range(offset, offset + eval(c2[3:]), 4):
                p.code[i:i+4] = b'\x60\x00\x00\x00'
                continue

        mylines = []

        mylines.append(MACROS)

        if c2.startswith(':'):
            mylines.append(' s')

            c2 = c2[1:]

            if re.match(r'^r\d+$', c2):
                mylines.append(' log "%s: %s = "' % (name, c2))
                mylines.append(' logreg %d' % int(c2[1:]))
                mylines.append(' logln ""')
            else:
                s = name
                if c2:
                    s += ': ' + c2
                mylines.append(' logln "%s"' % s)

            mylines.append(' r')
        else:
            mylines.extend(c2.split(';'))


        a = asm('\n'.join(mylines))

        try:
            patch(p.code, offset, a)
        except:
            pass

p.write_to(dest)
