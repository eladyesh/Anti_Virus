import os.path
from pprint import pprint
import yara
import sys
import subprocess


class YaraChecks:
    """
    A class containing methods for performing YARA rule checks on files.
    """

    @staticmethod
    def check_for_packer(exe):
        """
        Checks if an executable file is packed using YARA rules.

        Args:
            exe (str): The path to the executable file to be checked.

        Returns:
            dict: A dictionary mapping YARA rules that matched the file to their associated tags.
        """
        packers_rules = yara.compile(os.path.abspath("packers.yar").replace("graphics", "Yara"))
        packers_virus = packers_rules.match(exe)
        packers = {}

        # packers_upx = packers_rules.match("virus.exe")

        for rule in packers_virus:
            packers[rule] = rule.tags

        return packers

    @staticmethod
    def check_for_strings(exe):
        """
        Searches for suspicious strings in an executable file using YARA rules.

        Args:
            exe (str): The path to the executable file to be checked.

        Returns:
            tuple: A tuple containing:
                - list: A list of DLL names associated with the suspicious strings.
                - list: A list of suspicious strings found in the file.
                - list: A list of YARA rules that matched the file along with their metadata.
        """
        suspicious_strings_rules = yara.compile(os.path.abspath("check.yar").replace("graphics", "Yara"))
        suspicious_strings_matches = suspicious_strings_rules.match(exe)

        # #l = sorted([j for sub in [i.strings for i in matches] for j in sub], key= lambda tup: tup[0])
        dlls = []
        strings = []
        for i in suspicious_strings_matches:
            if i.meta != {}:
                dlls.append(i.meta['dll'])
            if i.strings:
                for j in i.strings:
                    strings.append(j[2])

        return dlls, strings, suspicious_strings_matches


if __name__ == '__main__':
    # Example usage
    YaraChecks.check_for_packer("virus.exe")
    print(YaraChecks.check_for_strings("virus.exe"))
