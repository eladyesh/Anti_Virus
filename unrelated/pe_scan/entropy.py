import math
import hashlib
import os.path

import pefile
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


def aes_encrypt(data, key):
    k = hashlib.sha256(key).digest()
    iv = 16 * '\x00'
    cipher = AES.new(k, AES.MODE_CBC, iv.encode("UTF-8"))
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return ciphertext


def shannon_entropy(data):
    # 256 different possible values
    possible = dict(((chr(x), 0) for x in range(0, 256)))

    for byte in data:
        possible[chr(byte)] += 1

    data_len = len(data)
    entropy = 0.0

    # compute
    for i in possible:
        if possible[i] == 0:
            continue

        p = float(possible[i] / data_len)
        entropy -= p * math.log(p, 2)
    return entropy


def entropy_for_file(file):
    with open(file, 'rb') as f:
        data = f.read()
        if data:
            entropy = shannon_entropy(data)
            return entropy


def encrypt_file(file):
    # key for encrypt/decrypt
    my_secret_key = get_random_bytes(16)
    with open("virus.exe", 'rb') as f:
        data = f.read()
        if data:
            # encrypted
            ciphertext = aes_encrypt(data, my_secret_key)
            with open("virus_encrypted.exe", "wb") as result:
                result.write(ciphertext)
    print("Done!")


def len_sections(path):
    return len(pefile.PE(path).sections)


def sections_entropy(path):
    sections = [[]]
    pe = pefile.PE(path)
    for section in pe.sections:
        # print(section.Name.decode())
        sections.append([section.Name.decode(), hex(section.VirtualAddress), hex(section.Misc_VirtualSize),
                         hex(section.SizeOfRawData),
                         str(shannon_entropy(section.get_data()))])
        # print("\tvirtual address: " + hex(section.VirtualAddress))
        # print("\tvirtual size: " + hex(section.Misc_VirtualSize))
        # print("\traw size: " + hex(section.SizeOfRawData))
        # print("\tentropy: " + str(shannon_entropy(section.get_data())))

    return sections


def entropy_vs_normal(path):
    file_entropy = 0
    res = []
    virus_secs = []
    reg_secs = []
    virus_entropy = entropy_for_file(os.path.abspath(path))
    reg_entropy = entropy_for_file(os.path.abspath("exe\\real_nop.exe").replace("graphics", "pe_scan"))

    if virus_entropy - reg_entropy > 0:
        file_entropy = virus_entropy - reg_entropy

    pe_virus = pefile.PE(os.path.abspath(path))
    pe_reg = pefile.PE(os.path.abspath("exe\\real_nop.exe").replace("graphics", "pe_scan"))
    for section_reg, section_virus in zip(pe_reg.sections, pe_virus.sections):
        if section_reg.Name.decode() == section_virus.Name.decode():
            if shannon_entropy(section_virus.get_data()) > shannon_entropy(section_reg.get_data()):
                res.append(section_reg.Name.decode())

    res.append(file_entropy)  # the last elem will be file entropy
    return res


if __name__ == "__main__":
    #   print(f"Entropy for virus.exe: {entropy_for_file('exe//virus.exe')}")
    #   print(f"Entropy for virus_encrypted.exe: {entropy_for_file('exe//virus_encrypted.exe')}")
    #   print(f"Entropy for hack.exe: {entropy_for_file('hack_viruses//hack.exe')}")
    #   print(f"Entropy for hack_encrypted.exe: {entropy_for_file('hack_viruses//hack_encrypted.exe')}")

    sections_entropy("exe//virus.exe")
    print()
    print()
    print()
    sections_entropy("exe//real_nop.exe")
