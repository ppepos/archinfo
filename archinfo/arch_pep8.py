import capstone as _capstone

try:
    import unicorn as _unicorn
except ImportError:
    _unicorn = None

from .arch import Arch
from .tls import TLSArchInfo

# FIXME: Tell fish to fix whatever he was storing in info['current_function']
# TODO: Only persist t9 in PIC programs

class ArchPEP8(Arch):
    def __init__(self, endness="Iend_LE"):
        super(ArchPEP8, self).__init__(endness)
        if endness == 'Iend_BE':

            self.function_prologs = {
                r"\x27\xbd\xff[\x00-\xff]"                                          # addiu $sp, xxx
                r"\x3c\x1c[\x00-\xff][\x00-\xff]\x9c\x27[\x00-\xff][\x00-\xff]"     # lui $gp, xxx; addiu $gp, $gp, xxxx
            }
            self.function_epilogs = {
                r"\x8f\xbf[\x00-\xff]{2}([\x00-\xff]{4}){0,4}\x03\xe0\x00\x08"      # lw ra, off(sp); ... ; jr ra
            }
            self.qemu_name = 'mips'
            self.triplet = 'mips-linux-gnu'
            self.linux_name = 'mips'

    bits = 16
    vex_arch = "VexArchPEP8"
    name = "PEP8"
    ida_processor = None
    qemu_name = None
    linux_name = None
    triplet = None
    max_inst_bytes = 3
    ip_offset = 22
    sp_offset = 20
    bp_offset = 120
    ret_offset = 8
    lr_offset = 124
    syscall_num_offset = 8
    call_pushes_ret = True
    stack_change = -2
    branch_delay_slot = True
    sizeof = {'short': 16, 'int': 32, 'long': 32, 'long long': 64}
    cs_arch = _capstone.CS_ARCH_MIPS
    cs_mode = _capstone.CS_MODE_32 + _capstone.CS_MODE_LITTLE_ENDIAN
    uc_arch = _unicorn.UC_ARCH_MIPS if _unicorn else None
    uc_mode = (_unicorn.UC_MODE_32 + _unicorn.UC_MODE_LITTLE_ENDIAN) if _unicorn else None
    uc_const = _unicorn.mips_const if _unicorn else None
    uc_prefix = "UC_MIPS_" if _unicorn else None
    function_prologs = {
        r"[\x00-\xff]\xff\xbd\x27",                                         # addiu $sp, xxx
        r"[\x00-\xff][\x00-\xff]\x1c\x3c[\x00-\xff][\x00-\xff]\x9c\x27"     # lui $gp, xxx; addiu $gp, $gp, xxxx
    }
    function_epilogs = {
        r"[\x00-\xff]{2}\xbf\x8f([\x00-\xff]{4}){0,4}\x08\x00\xe0\x03"      # lw ra, off(sp); ... ; jr ra
    }

    ret_instruction = "\x08\x00\xE0\x03" + "\x25\x08\x20\x00"
    nop_instruction = "\x00\x00\x00\x00"
    instruction_alignment = 4
    persistent_regs = ['gp', 'ra', 't9']

    default_register_values = [
        ( 'sp', Arch.initial_sp, True, 'global' ),   # the stack
    ]
    entry_register_values = {
    }

    default_symbolic_registers = ['a', 'x', 'sp', 'pc', 'n', 'z', 'v', 'c']

    register_names = {
       'host_EvC_FAILADDR':  0,
       'host_EvC_COUNTER':  4,
       'host_pad_1':  8,
       'host_pad_2':  12,
       'a': 16,
       'x': 18,
       'sp': 20,
       'pc': 22,
       'pc_at_syscall': 24,
       'n': 26,
       'z': 27,
       'v': 28,
       'c': 29,
       'pad_0':  30,
       'pad_1':  31
    }

    registers = {
       'host_EvC_FAILADDR':  (0, 4),
       'host_EvC_COUNTER':  (4, 4),
       'host_pad_1':  (8, 4),
       'host_pad_2':  (12, 4),
       'a': (16, 2),
       'x': (18, 2),
       'sp': (20, 2),
       'pc': (22, 2),
       'pc_at_syscall': (24, 2),
       'n': (26, 1),
       'z': (27, 1),
       'v': (28, 1),
       'c': (29, 1),
       'pad_0':  (30, 1),
       'pad_1':  (31, 1)
    }

    # argument_registers = {
    #     registers['v0'][0],
    #     registers['v1'][0],
    #     registers['a0'][0],
    #     registers['a2'][0],
    #     registers['a3'][0],
    #     registers['t0'][0],
    #     registers['t1'][0],
    #     registers['t2'][0],
    #     registers['t3'][0],
    #     registers['t4'][0],
    #     registers['t5'][0],
    #     registers['t6'][0],
    #     registers['t7'][0],
    #     registers['s0'][0],
    #     registers['s1'][0],
    #     registers['s2'][0],
    #     registers['s3'][0],
    #     registers['s4'][0],
    #     registers['s5'][0],
    #     registers['s6'][0],
    #     registers['t8'][0],
    #     registers['t9'][0]
    # }

    dynamic_tag_translation = {
        0x70000001: 'DT_MIPS_RLD_VERSION',
        0x70000005: 'DT_MIPS_FLAGS',
        0x70000006: 'DT_MIPS_BASE_ADDRESS',
        0x7000000a: 'DT_MIPS_LOCAL_GOTNO',
        0x70000011: 'DT_MIPS_SYMTABNO',
        0x70000012: 'DT_MIPS_UNREFEXTNO',
        0x70000013: 'DT_MIPS_GOTSYM',
        0x70000016: 'DT_MIPS_RLD_MAP',
        0x70000032: 'DT_MIPS_PLTGOT'
    }
    got_section_name = '.got'
    ld_linux_name = 'ld.so.1'
    elf_tls = TLSArchInfo(1, 8, [], [0], [], 0x7000, 0x8000)
