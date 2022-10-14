import os
import sys
import time
import json
import requests
import argparse
import hashlib


# for terminal colors
class Colors:
    BLUE = '\033[94m'  # static variables
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    ENDC = '\033[0m'

    # ------ MORE COLORS ------
    # HEADER = '\033[95m'
    # OKBLUE = '\033[94m'
    # OKCYAN = '\033[96m'
    # OKGREEN = '\033[92m'
    # WARNING = '\033[93m'
    # FAIL = '\033[91m'
    # ENDC = '\033[0m'
    # BOLD = '\033[1m'
    # UNDERLINE = '\033[4m'


def make_json(name, data):
    """
    function makes a json file of out data from the vt api
    :param name: the name of the file
    :param data: the json data
    :return: None
    """

    with open(name + ".json", "w") as f:
        json.dump(data, f)


# Virus Total API key
VT_API_KEY = r"9065bb9783e2196439ab5b9a99519c92674dedf381517bad08d7c3fbb8802987"  # your virus total api key

# VirusTotal API v3 URL
VT_API_URL = r"https://www.virustotal.com/api/v3/"


def md5(path):
    hash_md5 = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def sha_256(path):
    with open(os.path.abspath(path), "rb") as f:
        b = f.read()

        # creating a sha256 hash of the file
        hashsum = hashlib.sha256(b).hexdigest()
        return hashsum


def check_hash(hsh):
    try:
        if len(hsh) == 32:
            return hsh
        elif len(hsh) == 40:
            return hsh
        elif len(hsh) == 64:
            return hsh
        else:
            print("The Hash input does not appear valid.")
            exit()
    except Exception:
        print('There is something wrong with your hash \n' + Exception)


class VTScan:

    def __init__(self):
        # a dictionary of HTTP headers to send to the specified url.
        self.headers = {
            "x_apikey": VT_API_KEY,  # api key
            "User-Agent": "vtscan v.1.0",
            "Accept-Encoding": "gzip, deflate"
            # the client can accept a response which has been compressed using the DEFLATE algorithm
        }

    def info(self, file_hash):
        """
        function analyses file by it's has
        :param file_hash: the files hash
        :return: None
        """

        check_hash(file_hash)
        f = open("hash_check.txt", "w+")

        f.write("Getting file info by ID: " + file_hash + "\n\n")
        info_url = VT_API_URL + "files/" + file_hash
        res = requests.get(info_url, headers=self.headers)

        if res.status_code == 200:

            result = res.json()
            # make_json("info", result)
            if result.get("data").get("attributes").get("last_analysis_results"):

                stats = result.get("data").get("attributes").get("last_analysis_stats")
                results = result.get("data").get("attributes").get("last_analysis_results")
                f.write("malicious: " + str(stats.get("malicious")) + "\n")
                f.write("undetected : " + str(stats.get("undetected")) + "\n\n")
                print()
                for r in results:
                    if results[r].get("category") == "malicious":
                        f.write("==================================================" + "\n")
                        f.write(results[r].get("engine_name") + "\n")
                        f.write("version : " + results[r].get("engine_version") + "\n")
                        f.write("category : " + results[r].get("category") + "\n")
                        f.write("result : " +results[r].get("result") + "\n")
                        f.write("method : " + results[r].get("method") + "\n")
                        f.write("update : " + results[r].get("engine_update") + "\n")
                        f.write("==================================================" + "\n" * 3)

                f.write("successfully analyse: OK" + "\n")
                print("Scan Done successfully")
                sys.exit(1)

            else:
                f.write("failed to analyse :(..." + "\n")

        else:
            f.write("failed to get information :(" + "\n")
            f.write("status code: " + str(res.status_code) + "\n")
            sys.exit(1)


if __name__ == "__main__":

    # creating an argument parser
    # parser = argparse.ArgumentParser()

    # adding argument
    # parser.add_argument('-m', '--mal', required=True, help="PE file path for scanning")
    # args = vars(parser.parse_args())

    # running scan on suspicious file
    vtscan = VTScan()
    vtscan.info("243861e0c5b6f07248a033105e626189")
