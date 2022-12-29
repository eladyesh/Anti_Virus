import os.path
from pprint import pprint
import yara
import sys
import subprocess


class YaraChecks:

    @staticmethod
    def check_for_packer(exe):

        packers_rules = yara.compile(os.path.abspath("packers.yar").replace("graphics", "Yara"))
        packers_virus = packers_rules.match(exe)
        packers = {}

        # packers_upx = packers_rules.match("upx_ADExplorer.exe")

        for rule in packers_virus:
            packers[rule] = rule.tags

        return packers

    @staticmethod
    def check_for_strings(exe):

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

        return dlls, strings


if __name__ == '__main__':
    YaraChecks.check_for_packer("virus.exe")
    print(YaraChecks.check_for_strings("virus.exe"))
