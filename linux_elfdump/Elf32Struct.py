"""
@author:        Enrico Canzonieri
@license:       GNU General Public License 2.0 or later
@contact:       canzonie@eurecom.fr
"""


#--------------------------------------
# Auxiliary Vector from Elf_32_auxv_t in elf.h
#--------------------------------------

a_type = {
    "AT_NULL": 0,              # End of vector
    "AT_IGNORE": 1,            # Entry should be ignored
    "AT_EXECFD": 2,            # File descriptor of program
    "AT_PHDR": 3,              # Program headers for program
    "AT_PHENT": 4,             # Size of program header entry
    "AT_PHNUM": 5,             # Number of program headers
    "AT_PAGESZ": 6,             # System page size
    "AT_BASE": 7,              # Base address of interpreter
    "AT_FLAGS":  8,            # Flags
    "AT_ENTRY": 9,             # Entry point of program
    "AT_NOTELF": 10,           # Program is not ELF
    "AT_UID": 11,              # Real uid
    "AT_EUID": 12,             # Effective uid
    "AT_GID": 13,              # Real gid
    "AT_EGID": 14,             # Effective gid
    "AT_CLKTCK": 17,           # Frequency of times()
    "AT_PLATFORM": 15,         # String identifying platform.
    "AT_HWCAP": 16,            # Machine dependent hints about processor capabilities.
    "AT_FPUCW": 18,            # Used FPU control word.
    "AT_DCACHEBSIZE": 19,      # Data cache block size.
    "AT_ICACHEBSIZE": 20,      # Instruction cache block size.
    "AT_UCACHEBSIZE": 21,      # Unified cache block size.
    "AT_IGNOREPPC": 22,        # Entry should be ignored.
    "AT_SECURE": 23,           # Boolean, was exec setuid-like?
    "AT_BASE_PLATFORM": 24,      # String identifying real platforms.
    "AT_RANDOM": 25,           # Address of 16 random bytes.
    "AT_EXECFN": 31,           # Filename of executable.
    "AT_SYSINFO": 32,
    "AT_SYSINFO_EHDR": 33,
    "AT_L1I_CACHESHAPE": 34,
    "AT_L1D_CACHESHAPE": 35,
    "AT_L2_CACHESHAPE": 36,
    "AT_L3_CACHESHAPE": 37
}


#--------------------------------------
# Elf32_Phdr from elf.h
#--------------------------------------

phdr_types = {
    "PT_NULL": 0,               # Program header table entry unused
    "PT_LOAD": 1,               # Loadable program segment
    "PT_DYNAMIC": 2,               # Dynamic linking information
    "PT_INTERP": 3,               # Program interpreter
    "PT_NOTE": 4,               # Auxiliary information
    "PT_SHLIB": 5,               # Reserved
    "PT_PHDR": 6,               # Entry for header table itself
    "PT_TLS": 7,               # Thread-local storage segment
    "PT_NUM": 8               # Number of defined types
}

#--------------------------------------
# Elf32_Dyn from elf.h
#--------------------------------------

dynamic_entry_types = {
    "DT_NULL":  0,      # Marks end of dynamic section
    "DT_NEEDED": 1,     # Name of needed library
    "DT_PLTRELSZ": 2,       # Size in bytes of PLT relocs
    "DT_PLTGOT": 3,     # Processor defined value
    "DT_HASH": 4,       # Address of symbol hash table
    "DT_STRTAB": 5,     # Address of string table
    "DT_SYMTAB": 6,     # Address of symbol table
    "DT_RELA": 7,       # Address of Rela relocs
    "DT_RELASZ": 8,     # Total size of Rela relocs
    "DT_RELAENT": 9,        # Size of one Rela reloc
    "DT_STRSZ": 10,         # Size of string table
    "DT_SYMENT": 11,        # Size of one symbol table entry
    "DT_INIT": 12,      # Address of init function
    "DT_FINI": 13,      # Address of termination function
    "DT_SONAME": 14,        # Name of shared object
    "DT_RPATH": 15,     # Library search path (deprecated)
    "DT_SYMBOLIC": 16,      # Start symbol search here
    "DT_REL": 17,       # Address of Rel relocs
    "DT_RELSZ": 18,     # Total size of Rel relocs
    "DT_RELENT": 19,        # Size of one Rel reloc
    "DT_PLTREL": 20,        # Type of reloc in PLT
    "DT_DEBUG": 21,     # For debugging; unspecified
    "DT_TEXTREL": 22,       # Reloc might modify .text
    "DT_JMPREL": 23,        # Address of PLT relocs
    "DT_BIND_NOW": 24,      # Process relocations of object
    "DT_INIT_ARRAY": 25,        # Array with addresses of init fct
    "DT_FINI_ARRAY": 26,        # Array with addresses of fini fct
    "DT_INIT_ARRAYSZ": 27,      # Size in bytes of DT_INIT_ARRAY
    "DT_FINI_ARRAYSZ": 28,     # Size in bytes of DT_FINI_ARRAY
    "DT_RUNPATH": 29,      # Library search path
    "DT_FLAGS":    30,     # Flags for the object being loaded
    "DT_ENCODING": 32,     # Start of encoded range
    "DT_PREINIT_ARRAYSZ": 33       # size in bytes of DT_PREINIT_ARRAY
}
