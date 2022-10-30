import pefile
import pereader
from dataclasses import dataclass
import struct
import sys

# def listsections(fname):
#     pe = pefile.PE(fname)
#     print("Sections: ", end='')
#     print("\t\tEntropy\n")
#     for sect in pe.sections:
#         print("%17s" % sect.Name.decode('utf-8'), end='')
#         print(("\t\t%5.2f" % sect.get_entropy()))
#         print(sect)

@dataclass
class ScanPE:
    path: str
    suspicious_flags = ['IMAGE_SCN_MEM_EXECUTE', 'IMAGE_SCN_MEM_READ', 'IMAGE_SCN_MEM_WRITE']

    def scan_sections(self):
        """
        Patches in the Section Table
        A prominent red flag for non-packed files is the presence of write and execute characteristics in a section
        Most of the time write and execute characteristics do not appear together in a section in non-packed files,
        whereas it is rather typical for packed files.
        The presence of both means the code itself can be changed dynamically
        """
        pe = pereader.PE(self.path, is_entropy=False)
        for sect in pe.section_header:
            if self.suspicious_flags[0] in sect.flags and self.suspicious_flags[2] in sect.flags:
                print(sect.Name)

    def scan_imoprts(self):

        pe = pefile.PE(self.path)
        pe.parse_data_directories()
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(entry.address)
            # for imp in entry.imports:
            #     print('\t', imp.address, imp.name)


pe_scan = ScanPE("virus.exe")
pe_scan.scan_sections()
pe_scan.scan_imoprts()