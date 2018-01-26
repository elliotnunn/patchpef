#!/usr/bin/env python3

# REQUIRES VASM!

import struct
from subprocess import run, DEVNULL, PIPE
import tempfile
from collections import namedtuple
import re
from sys import argv
from macresources import read_rsrc_path, write_rsrc_path
from pefbinary import PEF

ILEN = 4 # length and alignment of PowerPC instruction
IMASK = 0xFFFFFFFF
XTOC = b'\x81\x82\xff\xff\x90\x41\x00\x14\x80\x0c\x00\x00\x80\x4c\x00\x04\x7c\x09\x03\xa6\x4e\x80\x04\x20'

def insn_to_int(insn):
    if len(insn) != ILEN:
        raise ValueError('bad insn len')
    return int.from_bytes(insn, byteorder='big')

def int_to_code(*the_ints): # can sneakily take multiple ints
    return b''.join(x.to_bytes(4, byteorder='big') for x in the_ints)

def make_branch(from_offset=None, to_offset=None, delta=None):
    """Assemble an unconditional relative branch instruction"""

    if delta is None:
        delta = to_offset - from_offset

    if not -(2**26) <= delta < 2**26:
        raise ValueError('branch out of range')

    if delta % 4:
        raise ValueError('branch not aligned')

    insn = (18 << 26) | (delta & 0x3FFFFFC)

    return int_to_code(insn)

def adjust_branch(insn, orig_loc=None, new_loc=None, delta=None):
    if delta is None:
        delta = orig_loc - new_loc # seems backwards but isnt

    as_int = insn_to_int(insn)
    major_opcode = as_int >> 26

    if major_opcode == 18:
        offset_bit_count = 26
    elif major_opcode == 16:
        offset_bit_count = 16
    else:
        return insn

    if as_int & 2:
        return insn # absolute branch (these are rare)

    offset_mask = (1 << offset_bit_count) - 1
    offset_mask &= ~3 # cut off two low flag bits

    keep_mask = IMASK ^ offset_mask

    most_extreme_offset = 1 << (offset_bit_count - 1)

    the_offset_bits = as_int & offset_mask

    the_offset = the_offset_bits
    if the_offset & (1 << (offset_bit_count - 1)):
        the_offset -= 1 << offset_bit_count

    the_new_offset = the_offset + delta

    # print('-------- old_offset', hex(the_offset), 'new_offset', hex(the_new_offset))

    if not -most_extreme_offset <= the_new_offset < most_extreme_offset:
        raise ValueError('does not fit')

    new_offset_bits = the_new_offset & offset_mask

    new_as_int = (as_int & keep_mask) | new_offset_bits

    return int_to_code(new_as_int)

def insn_can_fall_through(insn):
    as_int = insn_to_int(insn)
    if as_int in [0x4e800020, 0x4e800420, 0x4c000064]:
        return False
    elif as_int >> 26 == 18 and not as_int & 1:
        return False
    else:
        return True

def asm(code):
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write(code)
        input_tmp = f.name
    with tempfile.NamedTemporaryFile() as f:
        output_tmp = f.name

    run(['vasmppc_mot', '-Fbin', '-spaces', '-o', output_tmp, input_tmp], check=True, stdout=DEVNULL)

    with open(output_tmp, 'rb') as f:
        return f.read()

def scan_ppc_macsbug_symbols(bin):
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

def offsets_from_command_str(locstr, locdict):
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

def uproot_instruction(insn, orig_loc, new_loc):
    """The instruction might get expanded to three instructions!"""

    BC_MASK = 0xFFFF0003
    B = 0x48000000

    as_int = insn_to_int(insn)

    major_opcode = as_int >> 26
    is_abs = bool(as_int & 2)
    is_link = bool(as_int & 1)

    if as_int == 0x4e800020:
        print('---- single blr')
        return insn

    elif as_int == 0x4e800420:
        print('---- single bctr')
        return insn

    elif as_int == 0x4c000064:
        print('---- single rfi')
        return insn

    elif major_opcode == 18: # branch unconditional
        print('---- unconditional branch')
        new = insn

        if not is_abs:
            print('------ is pc-relative, adjusting...')
            new = adjust_branch(new, orig_loc=orig_loc, new_loc=new_loc)
        else:
            print('------ is absolute, not adjusting')

        if is_link:
            print('------ is linking (bl), appending branch back home')
            new += make_branch(from_offset=new_loc+4, to_offset=orig_loc+4)
        else:
            print('------ is non-linking')

        return new

    elif major_opcode == 16: # branch conditional
        print('---- conditional branch')
        new = insn

        try:
            new = adjust_branch(new, orig_loc=orig_loc, new_loc=new_loc)

        except ValueError: #does not fit!
            orig_bc_delta = as_int & (IMASK ^ BC_MASK)
            if orig_bc_delta & 0x8000: orig_bc_delta =- 0x10000
            print('------ is beyond adjustment range => "bc *+8; b back_home; b target"')

            new = int_to_code((as_int & BC_MASK) | 8)
            new += make_branch(from_offset=new_loc+4, to_offset=orig_loc+4)
            new += make_branch(from_offset=new_loc+8, to_offset=orig_loc+orig_bc_delta)

        else: # does fit!
            print('------ is within adjustment range => "bc target; b back_home"')
            new += make_branch(from_offset=new_loc+4, to_offset=orig_loc+4)

        return new

    else:
        print('---- non-special-case %08X, assuming fallthrough' % as_int)

        go_home = make_branch(from_offset=new_loc+4, to_offset=orig_loc+4)

        return insn + go_home


MACROS = """
    macro saveRegsInRedZone
    stmw    r0, -128(sp)
    mflr    r0
    stw     r0, -132(sp)
    endm

    macro s
    saveRegsInRedZone
    endm

    macro restoreRegsFromRedZone
    lwz     r0, -132(sp)
    mtlr    r0
    lmw     r3, -116(sp)
    lwz     r2, -120(sp)
    lwz     r0, -128(sp)
    endm

    macro r
    restoreRegsFromRedZone
    endm

    MACRO saveRTOC
    stw     r2, 20(sp)
    ENDM

    MACRO sr
    saveRTOC
    ENDM

    MACRO restoreRTOC
    lwz     r2, 20(sp)
    ENDM

    MACRO rr
    restoreRTOC
    ENDM

    MACRO prolog
framesize set \\1
    mflr    r0
    stw     r0, 8(sp)
    stwu    sp, -framesize(sp)
    IF amReplacingCrossTocGlue
    stw     r2, framesize+20(sp)
    ENDIF
    ENDM

    MACRO p
    prolog \\1
    ENDM

    MACRO epilog
    lwz     sp, framesize(sp)
    lwz     r0, 8(sp)
    mtlr    r0
    blr
    ENDM

    MACRO e
    epilog
    ENDM

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

p = PEF(read_rsrc_path(src))

locdict = {n: (o, l) for (o, l, n) in scan_ppc_macsbug_symbols(p.code)}

cmds = iter(cmds)

for c in cmds:
    ccc = next(cmds)

    for name, offset in offsets_from_command_str(c, locdict):
        c2 = ccc

        print('Patching "%s" @ %X' % (name, offset))

        if c2.startswith('nop'):
            for i in range(offset, offset + eval(c2[3:]), 4):
                p.code[i:i+4] = b'\x60\x00\x00\x00'
                continue

        am_replacing_xtoc_glue = False
        if len(p.code) >= offset + len(XTOC):
            xtoc = p.code[offset:offset+len(XTOC)]
            if xtoc[:2] == XTOC[:2] and xtoc[4:] == XTOC[4:]:
                print('-- patching over standard cross-TOC call glue:')
                print('     prolog/p macro will save RTOC to caller linkage area')
                print('     original glue is available using "xtoc" label')
                am_replacing_xtoc_glue = True


        mylines = []

        mylines.append('amReplacingCrossTocGlue equ %d' % am_replacing_xtoc_glue)

        mylines.append(MACROS)

        for n, (o, l) in locdict.items():
            mylines.append('%s equ $%X' % (n, o))

        mylines.append('comefrom equ $%X' % offset)
        mylines.append(' org $%X' % len(p.code))

        # reinsert clean cross-toc glue because the user probably wants to make a tail patch
        if am_replacing_xtoc_glue:
            if 'xtoc' in c2:
                print('---- inserting "xtoc" before your code')
                mylines.append('xtoc equ $%X' % len(p.code))
                p.code.extend(xtoc)
            else:
                print('---- no need to insert "xtoc"')

        if c2.startswith(':'):
            # Code auto-gen commands start with colon: :r3, :string
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
            # Otherwise, feed the assembler directly
            mylines.extend(c2.split(';'))


        a = asm('\n'.join(mylines))

        # for l in mylines:
        #     print(l)

        to_rescue = p.code[offset:offset+ILEN]

        get_here = make_branch(from_offset=offset, to_offset=len(p.code))
        p.code[offset:offset+ILEN] = get_here

        p.code.extend(a)

        if len(a) >= ILEN and insn_can_fall_through(a[-ILEN:]):
            print('-- your code falls through: appending their code')
            rescued = uproot_instruction(to_rescue, offset, len(p.code))
            p.code.extend(rescued)
        else:
            print('-- your code does not fall through: not appending anything')


write_rsrc_path(dest, bytes(p))
