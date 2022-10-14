import requests
import sys
import mysql.connector as mysql
import hashlib


def get_hash(link):
    url_response = requests.get(link)
    url_contents = url_response.text
    return url_contents[198:]


def get_row_count():
    cursor.execute("SELECT * FROM `hashes`")
    c = cursor.fetchall()
    print(sum([1 for i in c]))


def create_md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def main():
    for i in range(0, 100):

        page_num = (5 - len(str(i))) * "0" + str(i)
        hash = get_hash(f"https://virusshare.com/hashfiles/VirusShare_{page_num}.md5")

        for row in hash.split("\n"):
            sql = """INSERT INTO hashes(hash) VALUES (%s)"""
            cursor.execute(sql, (row,))

            db.commit()

        print(f"----GOT page number {i} / 100----")


if __name__ == "__main__":
    db = mysql.connect(
        host="localhost",
        user="root",
        passwd="eladyesh24@gmail.com",
        database="virus_hashes"
    )
    cursor = db.cursor()

    cursor.execute("SET GLOBAL max_allowed_packet=1073741824")

    md5_hash = create_md5("virus.exe")
    # cursor.execute("SELECT * FROM `hashes`")
    # c = cursor.fetchall()

    # for i in c:
    #     if md5_hash == i[0]:
    #         print("HASH matches a known virus hash")

    # cursor.execute("CREATE TABLE hashes (hash VARCHAR(255))")
    # cursor.execute("CREATE DATABASE virus_hashes")

    # main()
