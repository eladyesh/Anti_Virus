from pprint import pprint
import yara
import sys
import subprocess


class YaraChecks:

    @staticmethod
    def check_for_packer(exe):

        packers_rules = yara.compile("packers.yar")
        packers_virus = packers_rules.match("virus.exe")
        packers_upx = packers_rules.match("upx_ADExplorer.exe")

        for i in packers_virus:
            print(i)
        print("\n\n\n\n")

        print("\n\n\n\n")
        for i in packers_upx:
            print(i)

    @staticmethod
    def check_for_strings(exe):

        suspicious_strings_rules = yara.compile("check.yar")
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
    # YaraChecks.check_for_packer("virus.exe")
    print(YaraChecks.check_for_strings("virus.exe"))
