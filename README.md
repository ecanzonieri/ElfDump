======
ElfDump
======
What is Elfdump?
---------------------------------

Elfdump is a volatility plug-in to dump elf executables from memory dump.

Installing
----------

You have to install volatility last version from http://code.google.com/p/volatility/ . 
To install the plug-in is enough to copy the directory linux_elf_dump in volatility_root/volatility/plugins/

How to use it?
--------------

You can run volatility using linux_pslist or linux_psaux to get the PID of the process that you would dump.
The command used to dump the process in volatility is linux_elf_dump.

Available options:

    -p PID                  Operate on these Process IDs (comma-separated)
    -D Directory            Output directory

To execute the dumped elf it is necessary to set the environment variable **LD_BIND_NOW=1**, in order to force the dynamic linker to process all relocation before transferring control to the program (no lazy relocation).

Limitations
-----------
- No lazy relocation.
- Sections reconstruction is not implemented.
