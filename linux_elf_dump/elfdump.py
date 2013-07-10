"""
@author:        Enrico Canzonieri
@license:       GNU General Public License 2.0 or later
@contact:       canzonie@eurecom.fr
"""

import volatility.obj as obj
import volatility.plugins.linux.flags as linux_flags
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist
import ElfStruct
import volatility.debug as debug
import struct
import io
import os


class linux_elf_dump(linux_pslist.linux_pslist):
    """Reconstruct elf file from process in memory"""

    elfInfo = {}

    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option('DUMP-DIR', short_option = 'D', default = "./", \
         help = 'Output directory', action = 'store', type = 'str')

    def get_auxiliary_vector(self, task):
        proc_as = task.get_process_address_space()
        top_auxv = task.mm.env_start.v()
        stackbase = top_auxv & 0xFFFFF000
        debug.info("stackbase = 0x%x\n" % stackbase)
        entry = top_auxv
        found = False
        if self.elfInfo['ARCH'] == 'x86':
            entry_size = 0x04
            format = "<I"
        else:
            entry_size = 0x08
            format = "<Q"
        while not found:
#            if proc_as.is_valid_address(entry) and proc_as.is_valid_address(entry + entry_size):
            try:
#                debug.info("Entry %x" % entry)
                auxv_type_raw = proc_as.read(entry, entry_size)
                auxv_type = struct.unpack(format, auxv_type_raw)[0]
#                debug.info("Auxv type = %x\n" % auxv_type)
                auxv_value_raw = proc_as.read(entry+entry_size, entry_size)
                auxv_value = struct.unpack(format, auxv_value_raw)[0]
#                debug.info("Auxv value = %x\n" % auxv_value)
            except:
                entry -= 0x01
                if entry <= (stackbase):
                    debug.error("AT_PAGESZ not found. End Page reached. Entry =%x\n" % entry)
                continue
            if auxv_type == ElfStruct.a_type["AT_PAGESZ"] and auxv_value == 4096:
                found = True
            entry -= 0x01
            if entry <= (stackbase):
                debug.error("AT_PAGESZ not found. End Page reached. Entry =%x\n" % entry)
        found = False
        debug.info("AT_PAGESZ = %d at 0x%x\n" % (auxv_value, entry))
        while not found:
            auxv_type_raw = proc_as.read(entry, entry_size)
            auxv_type = struct.unpack(format, auxv_type_raw)[0]
            auxv_value_raw = proc_as.read(entry+entry_size, entry_size)
            auxv_value = struct.unpack(format, auxv_value_raw)[0]
            if auxv_type == ElfStruct.a_type["AT_NULL"] and auxv_value == 0x00:
                found = True
                bottom_auxv = entry
            entry -= 0x01
            if entry <= (stackbase):
                debug.error("AT_NULL not found. End Page reached. Entry = 0x%x \n" % bottom_auxv)
        debug.info("AT_NULL = %d at 0x%x\n" % (auxv_value, bottom_auxv))
        stop = False
        self.elfInfo["AUXV"] = {}
        while not stop:
            try:
                auxv_type_raw = proc_as.read(entry, entry_size)
                auxv_type = struct.unpack(format, auxv_type_raw)[0]
                auxv_value_raw = proc_as.read(entry+entry_size, entry_size)
                auxv_value = struct.unpack(format, auxv_value_raw)[0]
            except:
                entry += 0x01
                if entry >= top_auxv:
                    break
                continue
            if auxv_type == ElfStruct.a_type["AT_PHDR"]:
                self.elfInfo["AUXV"]["AT_PHDR"] = auxv_value
                debug.info("AT_PHDR found %x" % auxv_value)
            elif auxv_type == ElfStruct.a_type["AT_PHENT"]:
                self.elfInfo["AUXV"]["AT_PHENT"] = auxv_value
                debug.info("AT_PHENT found %x" % auxv_value)
            elif auxv_type == ElfStruct.a_type["AT_PHNUM"]:
                self.elfInfo["AUXV"]["AT_PHNUM"] = auxv_value
                debug.info("AT_PHNUM found %x" % auxv_value)
            elif auxv_type == ElfStruct.a_type["AT_BASE"]:
                self.elfInfo["AUXV"]["AT_BASE"] = auxv_value
                debug.info("AT_BASE found %x" % auxv_value)
            elif auxv_type == ElfStruct.a_type["AT_ENTRY"]:
                self.elfInfo["AUXV"]["AT_ENTRY"] = auxv_value
                debug.info("AT_ENTRY found %x" % auxv_value)
            elif auxv_type == ElfStruct.a_type["AT_RANDOM"]:
                self.elfInfo["AUXV"]["AT_RANDOM"] = auxv_value
                debug.info("AT_RANDOM found %x" % auxv_value)
            entry += 0x01
            if entry >= top_auxv:
                break
        debug.info("length = %d" %len(self.elfInfo["AUXV"]))
        if len(self.elfInfo["AUXV"]) != 6:
            debug.error("Something went wrong. Out of Auxiliary Vector.")
        debug.info("\n ::: Auxiliary Vector ::: \n")
        for k, v in self.elfInfo["AUXV"].iteritems():
            debug.info("|_%s --> 0x%x\n" % (k, v))
        return True


    def dumpFromPhdr(self, proc_as, filename):
        outfile = open(filename, "wb+")
        filesize = 0
        self.elfInfo["PHDR_ENTRIES"] = {}
        for i in range(0, self.elfInfo["AUXV"]["AT_PHNUM"] * self.elfInfo["AUXV"]["AT_PHENT"], self.elfInfo["AUXV"]["AT_PHENT"]):
            if self.elfInfo["ARCH"] == 'x86':
                phdr_entry = Elf32_PhdR()
            else:
                phdr_entry = Elf64_PhdR()
            phdr_entry.readFromDump(proc_as, self.elfInfo["AUXV"]["AT_PHDR"] + i)
            debug.info(phdr_entry)

            if not phdr_entry.p_type in self.elfInfo["PHDR_ENTRIES"]:
                self.elfInfo["PHDR_ENTRIES"][phdr_entry.p_type] = []
            self.elfInfo["PHDR_ENTRIES"][phdr_entry.p_type].append(phdr_entry)

            if phdr_entry.p_type == ElfStruct.phdr_types["PT_LOAD"]:
                if filesize < (phdr_entry.p_offset + phdr_entry.p_filesz):
                    filesize = phdr_entry.p_offset + phdr_entry.p_filesz
                debug.info("Dumping %x size %x \n" % (phdr_entry.p_vaddr, phdr_entry.p_filesz))
                raw = proc_as.zread(phdr_entry.p_vaddr, phdr_entry.p_filesz)
                outfile.seek(phdr_entry.p_offset)
                outfile.write(raw)
        debug.info("File size = %d\n" % filesize)
        outfile.close()
        return

    def resetElfHdr(self, filename):
        outfile = io.FileIO(filename, 'rb+')
        ### We cannot dump the section headers.
        ### We have to set the fields e_shoff, e_shstrndx, e_shentsize, e_shnum of the Elf header to zero
        ## offset of e_shoff
        ## 32 bit  --> 32 = 16 + 2 + 2 + 4 + 4 + 4. From elf.h
        ## 64 bit  --> 48 = 16 + 2 + 2 + 4 + 8 +8
        if self.elfInfo['ARCH'] == 'x86':
            offset = 32
            size = 4
        else:
            offset = 40
            size = 8
        outfile.seek(offset, io.SEEK_SET)  # offset of e_shoff
        for i in range(0, size):
            outfile.write('\0')
        ## offset of e_shentsize
        ## 32 / 64 Bit  --> 10 = 4 + 2 + 2 + 2
        offset = 10
        ## 32 / 64 bit same size
        size = 6
        outfile.seek(offset, io.SEEK_CUR)  # offset of e_shentsize
        for i in range(0, size):  # set e_shentsize, e_shnum and e_shstrndx to zero
            outfile.write('\0')
        debug.info("Checking Entry point...")
        ## offset entry point
        ## 32 / 64 bit --> 24 = 16 + 2 + 2 + 4 
        offset = 24
        if self.elfInfo['ARCH'] == 'x86':
            size = 4
            format = "<I"
        else:
            size = 8
            format = "<Q"
        outfile.seek(24, io.SEEK_SET)
        raw = outfile.read(size)
        entry = struct.unpack(format, raw)[0]
        debug.info("Entry point in file = 0x%x\n" % entry)
        if not entry == self.elfInfo["AUXV"]["AT_ENTRY"]:
            debug.info("Entry point in Header is different from the one in Auxiliary Vector 0x%x type\n" % self.elfInfo["AUXV"]["AT_ENTRY"])
        debug.info("Checking PHDR... \n")
        ## offset e_phoff
        ## 32 bit --> 28 = 16 + 2 + 2 + 4 + 4
        ## 64 bit --> 32 = 16 + 2 + 2 + 4 + 8
        if self.elfInfo['ARCH'] == 'x86':
            offset = 28
            format = "<I"
            size = 4
        else:
            offset = 32
            format = "<Q"
            size = 8
        outfile.seek(offset, io.SEEK_SET)
        raw = outfile.read(size)
        phdr_addr = struct.unpack(format, raw)[0]
        ## offset e_phentsize
        ## 32 bit --> 10 = 4 + 4 + 2
        ## 64 bit --> 14 = 8 + 4 +2
        ## same size
        if self.elfInfo['ARCH'] == 'x86':
            offset = 10
        else:
            offset = 14
        outfile.seek(offset, io.SEEK_CUR)
        raw = outfile.read(2)
        phdr_size = struct.unpack('<H', raw)[0]
        raw = outfile.read(2)
        phdr_num = struct.unpack('<H', raw)[0]
        if self.elfInfo['ARCH'] == 'x86':
            phdr_entry = Elf32_PhdR()
        else:
            phdr_entry = Elf64_PhdR()
        debug.info("Program header address = 0x%x size = %d num = %d \n" % (phdr_addr, phdr_size, phdr_num))
        for i in range(phdr_addr, phdr_size * phdr_num, phdr_size):
            phdr_entry.readFromFile(outfile, i)
            debug.info(phdr_entry)
        outfile.close()

    ###Not useful for now, run the dumped program using LD_BIND_NOW = 1
    def restorePlt(self, filename, proc_as):
        #outfile = io.FileIO(filename, 'rb+')
        #Starting from PHdr PT_DYNAMIC I get the dynamic linking information, I am interested in
        # DT_SYMTAB (address of symbol table) to locate each symbol and DT_PLTGOT
        debug.info("Looking at the content of dynamic header in the memory dump...")
        addr = self.elfInfo["PHDR_ENTRIES"][ElfStruct.phdr_types["PT_DYNAMIC"]][0].p_vaddr
        if self.elfInfo['ARCH'] == 'x86':
            dynamic_entry = Elf32_Dyn()
        else:
            dynamic_entry = Elf64_Dyn()
        dynamic_entry.readFromDump(proc_as, addr)
        while not dynamic_entry.d_tag == ElfStruct.dynamic_entry_types['DT_NULL']:
            debug.info(dynamic_entry)
            addr += 0x08
            dynamic_entry.readFromDump(proc_as, addr)
            # if dynamic_entry.d_tag == ElfStruct.dynamic_entry_types['DT_PLTGOT']:
        debug.info(dynamic_entry)
        #outfile.close()
        return

    def calculate(self):
        if not self._config.PID:
            debug.error("You have to specify a process to dump. Use the option -p.\n")
        #Retrieve the task_struct of the process
        tasks = linux_pslist.linux_pslist.calculate(self)
        for task in tasks:
            if task.mm:
                yield task

    def render_text(self, outfd, data):
        if (not os.path.isdir(self._config.DUMP_DIR)):
            debug.error("Please specify an existing output dir (--dump-dir)")
        linux_common.set_plugin_members(self)
        if self.profile.metadata.get('arch').lower() == 'x86':
            self.elfInfo['ARCH'] = 'x86'
            debug.info("x86 Architecture \n")
        elif self.profile.metadata.get('arch').lower() == 'x64':
            self.elfInfo['ARCH'] = 'x64'
            debug.info("x64 Architecture \n")
        dumped = []
        for task in data:
            #retrieve the auxiliary vector for the process
            debug.info("Looking for auxiliary_vector process PID = %s" % self._config.PID)
            self.get_auxiliary_vector(task)
            proc_as = task.get_process_address_space()
            #create a the elf file of the process
            file_name = task.comm + '.dump'
            file_path = os.path.join(self._config.DUMP_DIR, file_name)
            self.dumpFromPhdr(proc_as, file_path)
            debug.info("Reset elf\n")
            self.resetElfHdr(file_path)
            self.restorePlt(file_path, proc_as)
            dumped.append(task)
        outfd.write("Dumped Process:\n")
        self.table_header(outfd, [("Offset", "[addrpad]"),
                                  ("Name", "20"),
                                  ("Pid", "15"),
                                  ("Uid", "15"),
                                  ("Start Time", "")])
        for task in dumped:
            self.table_row(outfd, task.obj_offset,
                task.comm,
                str(task.pid),
                str(task.uid) if task.uid else "-",
                task.get_task_start_time())


class Elf64_Dyn:

    def readFromDump(self, proc_as, addr):
        self.addr = addr
        raw = proc_as.read(addr, 0x08)
        self.d_tag = struct.unpack("<q", raw)[0]    # D_TAG
        raw = proc_as.read(addr + 0x08, 0x08)
        self.d_val = struct.unpack("<q", raw)[0]    # D_VAL or D_PTR

    def readFromFile(self, fileio, addr):
        self.addr = addr
        fileio.seef(addr, io.SEEK_SET)
        raw =  fileio.read(0x08)
        self.d_tag = struct.unpack("<q", raw)[0]    # D_TAG
        raw =  fileio.read(0x08)
        self.d_val = struct.unpack("<q", raw)[0]    # D_VAL or D_PTR

    def __str__(self):
        text = "Dynamic section entry address: {0:#0{1}x}\n".format(self.addr, 10)
        text += "\td_tag: {0:#0{1}x} ---> ".format(self.d_tag, 10)
        for k, v in ElfStruct.dynamic_entry_types.iteritems():
            if v == self.d_tag:
                text += k + "\n"
                break
        text += "\td_val: {0:#0{1}x}\n".format(self.d_val, 10)
        return text


class Elf32_Dyn:

    def readFromDump(self, proc_as, addr):
        self.addr = addr
        raw = proc_as.read(addr, 0x04)
        self.d_tag = struct.unpack("<i", raw)[0]    # D_TAG
        raw = proc_as.read(addr + 0x04, 0x04)
        self.d_val = struct.unpack("<i", raw)[0]    # D_VAL or D_PTR

    def readFromFile(self, fileio, addr):
        self.addr = addr
        fileio.seef(addr, io.SEEK_SET)
        raw =  fileio.read(0x04)
        self.d_tag = struct.unpack("<i", raw)[0]    # D_TAG
        raw =  fileio.read(0x04)
        self.d_val = struct.unpack("<i", raw)[0]    # D_VAL or D_PTR

    def __str__(self):
        text = "Dynamic section entry address: {0:#0{1}x}\n".format(self.addr, 10)
        text += "\td_tag: {0:#0{1}x} ---> ".format(self.d_tag, 10)
        for k, v in ElfStruct.dynamic_entry_types.iteritems():
            if v == self.d_tag:
                text += k + "\n"
                break
        text += "\td_val: {0:#0{1}x}\n".format(self.d_val, 10)
        return text


class Elf64_PhdR:

    def readFromDump(self, proc_as, addr):
        self.phdr_addr = addr
        raw = proc_as.read(addr, 0x04)
        self.p_type = struct.unpack("<I", raw)[0]       # P_TYPE
        raw = proc_as.read(addr + 0x04, 0x04)
        self.p_flags = struct.unpack("<I", raw)[0]      # P_FLAGS
        raw = proc_as.read(addr + 0x08, 0x08)
        self.p_offset = struct.unpack("<Q", raw)[0]     # P_OFFSET
        raw = proc_as.read(addr + 0x10, 0x08)
        self.p_vaddr = struct.unpack("<Q", raw)[0]      # P_VADDR
        raw = proc_as.read(addr + 0x18, 0x08)
        self.p_paddr = struct.unpack("<Q", raw)[0]      # P_PADDR
        raw = proc_as.read(addr + 0x20, 0x08)
        self.p_filesz = struct.unpack("<Q", raw)[0]     # P_FILESZ
        raw = proc_as.read(addr + 0x28, 0x08)
        self.p_memsz = struct.unpack("<Q", raw)[0]      # P_MEMSZ
        raw = proc_as.read(addr + 0x30, 0x08)
        self.p_align = struct.unpack("<Q", raw)[0]      # P_ALIGN

    def readFromFile(self, fileio, addr):
        self.phdr_addr = addr
        fileio.seek(addr, io.SEEK_SET)
        raw = fileio.read(0x04)
        self.p_type = struct.unpack("<I", raw)[0]       # P_TYPE
        raw = fileio.read(0x04)
        self.p_flags = struct.unpack("<I", raw)[0]      # P_FLAGS
        raw = fileio.read(0x08)
        self.p_offset = struct.unpack("<Q", raw)[0]     # P_OFFSET
        raw = fileio.read(0x08)
        self.p_vaddr = struct.unpack("<Q", raw)[0]      # P_VADDR
        raw = fileio.read(0x08)
        self.p_paddr = struct.unpack("<Q", raw)[0]      # P_PADDR
        raw = fileio.read(0x08)
        self.p_filesz = struct.unpack("<Q", raw)[0]     # P_FILESZ
        raw = fileio.read(0x08)
        self.p_memsz = struct.unpack("<Q", raw)[0]      # P_MEMSZ
        raw = fileio.read(0x08)
        self.p_align = struct.unpack("<Q", raw)[0]      # P_ALIGN

    def __str__(self):
        text = "PhdR address: {0:#0{1}x}\n".format(self.phdr_addr, 10)
        text += "\tp_type: {0:#0{1}x} ---> ".format(self.p_type, 10)
        for k, v in ElfStruct.phdr_types.iteritems():
            if v == self.p_type:
                text += k + "\n"
                break
        text += "\tp_offset: {0:#0{1}x}\n".format(self.p_offset, 10)
        text += "\tp_vaddr: {0:#0{1}x}\n".format(self.p_vaddr, 10)
        text += "\tp_paddr: {0:#0{1}x}\n".format(self.p_paddr, 10)
        text += "\tp_filesz: {0:#0{1}x}\n".format(self.p_filesz, 10)
        text += "\tp_memsz: {0:#0{1}x}\n".format(self.p_memsz, 10)
        text += "\tp_flags: {0:#0{1}x}\n".format(self.p_flags, 10)
        text += "\tp_align: {0:#0{1}x}\n".format(self.p_align, 10)
        return text


class Elf32_PhdR:

    def readFromDump(self, proc_as, addr):
        self.phdr_addr = addr
        raw = proc_as.read(addr, 0x04)
        self.p_type = struct.unpack("<I", raw)[0]       # P_TYPE
        raw = proc_as.read(addr + 0x04, 0x04)
        self.p_offset = struct.unpack("<I", raw)[0]     # P_OFFSET
        raw = proc_as.read(addr + 0x08, 0x04)
        self.p_vaddr = struct.unpack("<I", raw)[0]      # P_VADDR
        raw = proc_as.read(addr + 0x0c, 0x04)
        self.p_paddr = struct.unpack("<I", raw)[0]      # P_PADDR
        raw = proc_as.read(addr + 0x10, 0x04)
        self.p_filesz = struct.unpack("<I", raw)[0]     # P_FILESZ
        raw = proc_as.read(addr + 0x14, 0x4)
        self.p_memsz = struct.unpack("<I", raw)[0]      # P_MEMSZ
        raw = proc_as.read(addr + 0x18, 0x4)
        self.p_flags = struct.unpack("<I", raw)[0]      # P_FLAGS
        raw = proc_as.read(addr + 0x1c, 0x4)
        self.p_align = struct.unpack("<I", raw)[0]      # P_ALIGN

    def readFromFile(self, fileio, addr):
        self.phdr_addr = addr
        fileio.seek(addr, io.SEEK_SET)
        raw = fileio.read(0x04)
        self.p_type = struct.unpack("<I", raw)[0]       # P_TYPE
        raw = fileio.read(0x04)
        self.p_offset = struct.unpack("<I", raw)[0]     # P_OFFSET
        raw = fileio.read(0x04)
        self.p_vaddr = struct.unpack("<I", raw)[0]      # P_VADDR
        raw = fileio.read(0x04)
        self.p_paddr = struct.unpack("<I", raw)[0]      # P_PADDR
        raw = fileio.read(0x04)
        self.p_filesz = struct.unpack("<I", raw)[0]     # P_FILESZ
        raw = fileio.read(0x04)
        self.p_memsz = struct.unpack("<I", raw)[0]      # P_MEMSZ
        raw = fileio.read(0x04)
        self.p_flags = struct.unpack("<I", raw)[0]      # P_FLAGS
        raw = fileio.read(0x04)
        self.p_align = struct.unpack("<I", raw)[0]      # P_ALIGN

    def __str__(self):
        text = "PhdR address: {0:#0{1}x}\n".format(self.phdr_addr, 10)
        text += "\tp_type: {0:#0{1}x} ---> ".format(self.p_type, 10)
        for k, v in ElfStruct.phdr_types.iteritems():
            if v == self.p_type:
                text += k + "\n"
                break
        text += "\tp_offset: {0:#0{1}x}\n".format(self.p_offset, 10)
        text += "\tp_vaddr: {0:#0{1}x}\n".format(self.p_vaddr, 10)
        text += "\tp_paddr: {0:#0{1}x}\n".format(self.p_paddr, 10)
        text += "\tp_filesz: {0:#0{1}x}\n".format(self.p_filesz, 10)
        text += "\tp_memsz: {0:#0{1}x}\n".format(self.p_memsz, 10)
        text += "\tp_flags: {0:#0{1}x}\n".format(self.p_flags, 10)
        text += "\tp_align: {0:#0{1}x}\n".format(self.p_align, 10)
        return text
