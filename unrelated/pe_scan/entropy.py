import math
import hashlib
import os.path

import pefile
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


def aes_encrypt(data, key):
    """
    Encrypts data using AES encryption with the provided key.

    Args:
        data (bytes): The data to be encrypted.
        key (bytes): The encryption key.

    Returns:
        bytes: The encrypted ciphertext.
    """
    k = hashlib.sha256(key).digest()
    iv = 16 * '\x00'
    cipher = AES.new(k, AES.MODE_CBC, iv.encode("UTF-8"))
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return ciphertext


def shannon_entropy(data):
    """
    Computes the Shannon entropy of the given data.

    Args:
        data (bytes): The data for entropy calculation.

    Returns:
        float: The Shannon entropy value.
    """
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
    """
    Computes the Shannon entropy for the contents of the given file.

    Args:
        file (str): The path to the file.

    Returns:
        float: The Shannon entropy value for the file's contents.
    """
    with open(file, 'rb') as f:
        data = f.read()
        if data:
            entropy = shannon_entropy(data)
            return entropy


def encrypt_file(file):
    """
    Encrypts the contents of the specified file using AES encryption and saves the encrypted ciphertext to a new file.

    Args:
        file (str): The path to the file to be encrypted.

    """
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
    """
    Calculates the number of sections in the given PE file.

    Args:
        path (str): The path to the PE file.

    Returns:
        int: The number of sections in the PE file.
    """
    return len(pefile.PE(path).sections)


def sections_entropy(path):
    """
    Calculates the entropy of each section in the given PE file.

    Args:
        path (str): The path to the PE file.

    Returns:
        list: A list of lists containing section information: name, virtual address, virtual size, raw size, and entropy.
    """
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
    """
    Calculates the entropy difference between a given file and a reference file, and identifies sections with higher entropy.

    Args:
        path (str): The path of the file to analyze.

    Returns:
        list: A list containing the names of sections with higher entropy than the reference file and the file entropy.
    """
    file_entropy = 0
    res = []
    virus_secs = []
    reg_secs = []

    # Calculate entropy for the virus file and the reference file
    virus_entropy = entropy_for_file(os.path.abspath(path))
    reg_entropy = entropy_for_file(os.path.abspath("exe\\real_nop.exe").replace("graphics", "pe_scan"))

    # Calculate the difference between virus entropy and reference entropy
    if virus_entropy - reg_entropy > 0:
        file_entropy = virus_entropy - reg_entropy

    # Load the virus file and the reference file using pefile library
    pe_virus = pefile.PE(os.path.abspath(path))
    pe_reg = pefile.PE(os.path.abspath("exe\\real_nop.exe").replace("graphics", "pe_scan"))

    # Compare the sections of the virus file and the reference file
    for section_reg, section_virus in zip(pe_reg.sections, pe_virus.sections):

        # Check if the section names match
        if section_reg.Name.decode() == section_virus.Name.decode():

            # Compare the entropy of the section data
            if shannon_entropy(section_virus.get_data()) > shannon_entropy(section_reg.get_data()):

                # Append the section name to the result list
                res.append(section_reg.Name.decode())

    # Append the file entropy to the result list
    res.append(file_entropy)
    return res

if __name__ == "__main__":
    #   print(f"Entropy for virus.exe: {entropy_for_file('exe//virus.exe')}")
    #   print(f"Entropy for virus_encrypted.exe: {entropy_for_file('exe//virus_encrypted.exe')}")
    #   print(f"Entropy for hack.exe: {entropy_for_file('hack_viruses//hack.exe')}")
    #   print(f"Entropy for hack_encrypted.exe: {entropy_for_file('hack_viruses//hack_encrypted.exe')}")

    print(entropy_for_file(r"D:\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated\pe_scan\exe\py_virus.exe"))
    print()
    print()
    print()
    print(entropy_for_file(r"D:\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated\pe_scan\exe\real_nop.exe"))
