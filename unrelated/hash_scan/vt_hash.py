import os
import sys
import threading
import time
import json
import requests
import argparse
import hashlib
import base64
import subprocess
import pydivert
import re
from http.server import HTTPServer, BaseHTTPRequestHandler


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<html>")
        self.wfile.write(b"<head><title>My Page</title></head>")
        self.wfile.write(b"<body>")
        self.wfile.write(b"<div style='text-align: center'>")
        self.wfile.write(b"<h1 style='margin-top: 70px;font-size:80px'>Hello User</h1>")
        for i in range(2):
            self.wfile.write(b"</br>")
        self.wfile.write(b"<p style='font-size: 60px;'>You have entered a website that was found suspicious by my "
                         b"AntiVirus</p>")
        self.wfile.write(b"</br>")
        self.wfile.write(b"<p style='font-size: 60px;'>You will now not be able to address this website</p>")
        self.wfile.write(b"</div>")
        self.wfile.write(b"</body>")
        self.wfile.write(b"</html>")


def start_server():
    httpd = HTTPServer(("192.168.1.12", 8080), RequestHandler)
    httpd.serve_forever()


def run_command(cmd):
    """
    runs cmd command in the command prompt and returns the output
    arg: cmd
    ret: the output of the command
    """
    with subprocess.Popen(cmd, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,
                          stdin=subprocess.PIPE) as proc:
        return proc.stdout.read()


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
VT_API_KEY = r"9065bb9783e2196439ab5b9a99519c92674dedf381517bad08d7c3fbb8802987"

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
        self.f = open("hash_check.txt", "w")

    def upload(self, malware_path):
        """
        function uploads suspicious file into malware_path
        :param malware_path: the path of the suspicious file
        :return: None
        """
        self.f.write("\nupload file: " + malware_path + "..." + "\n")
        self.malware_path = malware_path
        upload_url = VT_API_URL + "files"

        # a dictionary of files to send to the specified url
        files = {"file": (os.path.basename(malware_path),
                          open(os.path.abspath(malware_path), "rb"))}  # the requested format for posting
        self.f.write("upload to " + upload_url + "\n" * 2)
        res = requests.post(upload_url, headers=self.headers, files=files)

        # if requested post successful and the server responded with the data
        if res.status_code == 200:

            # make json format
            result = res.json()

            # writing to json file
            # make_json("upload", result)

            self.file_id = result.get("data").get("id")
            self.f.write("ID: " + self.file_id + "\n")
            self.f.write("successfully upload PE file: OK" + "\n")

        # not ok
        else:
            self.f.write("failed to upload PE file :(" + "\n")
            self.f.write("status code: " + str(res.status_code) + "\n")
            sys.exit(1)

    def analyse(self):
        """
        function analyses the files uploaded from Virus Total
        :return: None
        """

        self.f.write("\n\nGetting info about your file...." + "\n\n")
        analysis_url = VT_API_URL + "analyses/" + self.file_id
        res = requests.get(analysis_url, headers=self.headers)
        if res.status_code == 200:
            result = res.json()
            # make_json("analyse", result)
            status = result.get("data").get("attributes").get("status")

            # if analysis was completed
            if str(status) == "completed":
                stats = result.get("data").get("attributes").get("stats")
                results = result.get("data").get("attributes").get("results")
                self.f.write("malicious: " + str(stats.get("malicious")) + "\n")
                self.f.write("undetected : " + str(stats.get("undetected")) + "\n\n")
                self.f.write("")
                for r in results:
                    if results[r].get("category") == "malicious":
                        self.f.write("==================================================" + "\n")
                        self.f.write(results[r].get("engine_name") + "\n")
                        self.f.write("version : " + results[r].get("engine_version") + "\n")
                        self.f.write("category : " + results[r].get("category") + "\n")
                        self.f.write("result : " + results[r].get("result") + "\n")
                        self.f.write("method : " + results[r].get("method") + "\n")
                        self.f.write("update : " + results[r].get("engine_update") + "\n")
                        self.f.write("==================================================" + "\n" * 3)
                self.f.write("successfully analyse: OK" + "\n")
                sys.exit(1)

            # or queued....
            elif status == "queued":
                self.f.write("status QUEUED...")
                with open(os.path.abspath(self.malware_path), "rb") as fi:
                    b = fi.read()

                    # creating a sha256 hash of the file
                    hashsum = hashlib.sha256(b).hexdigest()
                    self.info(hashsum)
        else:
            self.f.write("failed to get results of analysis :(" + "\n")
            self.f.write("status code: " + str(res.status_code) + "\n")
            sys.exit(1)

    @staticmethod
    def scan_for_suspicious_cache():

        ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        ip_match = []
        block_ip = ["185.51.231.193", "205.251.196.240", "13.107.238.1", "13.107.6.254"]
        #dns_cache = run_command(["ipconfig", "/displaydns"]).decode()
        #for line in dns_cache.split("\r\n"):
        #    if ip_pattern.search(line) is not None:
        #        ip_match.append(ip_pattern.search(line)[0])

        #ip_match.remove("127.0.0.1")

        #url_to_vt = "https://www.virustotal.com/api/v3/urls/"

        # for ip in ip_match:
        #     url_to_check = base64.urlsafe_b64encode(ip.encode()).decode().strip("=")
        #     res = requests.get(url_to_vt + url_to_check, headers=self.headers)
        #     if res.status_code == 200:
        #         result = res.json()
        #         # print(result["data"]["attributes"]["last_analysis_results"]) --> engines
        #         if result["data"]["attributes"]["last_analysis_stats"]["malicious"] > 5:
        #             block_ip.append(ip)

        print("here")
        server_thread = threading.Thread(target=start_server)
        server_thread.start()

        with pydivert.WinDivert() as w:
            for packet in w:
                if packet.dst_addr in block_ip:
                    ip = packet.dst_addr
                    # print("packet dst in block ip ", packet.src_port, packet.dst_port, packet.src_addr, packet.dst_addr,packet.direction)
                    # print(f"got here out {packet.is_outbound}")
                    packet.dst_addr = "192.168.1.12"
                    packet.dst_port = 8080
                    packet.direction = 0
                    # print("packet modified ", packet.src_port, packet.dst_port, packet.src_addr, packet.dst_addr, packet.direction)
                if packet.src_addr == "192.168.1.12" and packet.src_port == 8080:
                    # print("packet src http ", packet.src_port, packet.dst_port, packet.src_addr, packet.dst_addr,
                    #       packet.direction)
                    packet.src_addr = ip
                    packet.src_port = 80
                    packet.direction = 1
                    # print("packet modified ", packet.src_port, packet.dst_port, packet.src_addr, packet.dst_addr,
                    #       packet.direction)
                w.send(packet)

    @staticmethod
    def scan_directory(path):

        headers = {
            "x_apikey": VT_API_KEY,  # api key
            "User-Agent": "vtscan v.1.0",
            "Accept-Encoding": "gzip, deflate"
            # the client can accept a response which has been compressed using the DEFLATE algorithm
        }

        for filename in os.scandir(path):
            if filename.is_file():

                upload_url = VT_API_URL + "files"

                # a dictionary of files to send to the specified url
                files = {"file": (os.path.basename(filename.path),
                                  open(os.path.abspath(filename.path), "rb"))}  # the requested format for posting
                res = requests.post(upload_url, headers=headers, files=files)

                if res.status_code == 200:

                    result = res.json()
                    file_id = result.get("data").get("id")
                    print("Successfully uploaded")

                    analysis_url = VT_API_URL + "analyses/" + file_id
                    analyse_res = requests.get(analysis_url, headers=headers)

                    if analyse_res.status_code == 200:
                        analyse_result = analyse_res.json()
                        print(analyse_result["data"]["attributes"]["stats"])
                else:
                    print("Could not upload successfully")

    def info(self, file_hash):
        """
        function analyses file by it's hash
        :param file_hash: the files hash
        :return: None
        """

        check_hash(file_hash)

        self.f.write("Getting file info by ID: " + file_hash + "\n\n")
        info_url = VT_API_URL + "files/" + file_hash
        res = requests.get(info_url, headers=self.headers)

        if res.status_code == 200:

            result = res.json()

            # make_json("info", result)
            if result.get("data").get("attributes").get("last_analysis_results"):

                stats = result.get("data").get("attributes").get("last_analysis_stats")
                results = result.get("data").get("attributes").get("last_analysis_results")
                self.f.write("malicious: " + str(stats.get("malicious")) + "\n")
                self.f.write("undetected : " + str(stats.get("undetected")) + "\n\n")
                self.f.write("")
                for r in results:
                    if results[r].get("category") == "malicious":
                        self.f.write("==================================================" + "\n")
                        self.f.write(results[r].get("engine_name") + "\n")
                        self.f.write("version : " + results[r].get("engine_version") + "\n")
                        self.f.write("category : " + results[r].get("category") + "\n")
                        self.f.write("result : " + results[r].get("result") + "\n")
                        self.f.write("method : " + results[r].get("method") + "\n")
                        self.f.write("update : " + results[r].get("engine_update") + "\n")
                        self.f.write("==================================================" + "\n" * 3)

                self.f.write("successfully analyse: OK" + "\n")
                print("Scan Done successfully")
                sys.exit(1)

            else:
                self.f.write("failed to analyse :(..." + "\n")

        else:
            self.f.write("failed to get information :(" + "\n")
            self.f.write("status code: " + str(res.status_code) + "\n")
            sys.exit(1)


if __name__ == "__main__":
    # creating an argument parser
    # parser = argparse.ArgumentParser()

    # adding argument
    # parser.add_argument('-m', '--mal', required=True, help="PE file path for scanning")
    # args = vars(parser.parse_args())

    # running scan on suspicious file
    # md5_hash = md5("nop.exe")
    # vtscan = VTScan()
    # vtscan.info(md5_hash)
    # vtscan.analyse()
    VTScan.scan_for_suspicious_cache()
    # VTScan.scan_directory("D:\Cyber\Sockets")
