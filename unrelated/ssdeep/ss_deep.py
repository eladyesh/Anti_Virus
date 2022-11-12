from multiprocessing import Queue, Process
from threading import Thread
import ppdeep

# h1 = ppdeep.hash_from_file("nop.exe")
# h2 = ppdeep.hash_from_file("virus.exe")
# print(ppdeep.compare(h1, h2))

h1 = ppdeep.hash_from_file("real_nop.exe")
counter = 0

def search_49_file():
    global counter
    with open("ssdeep_datasets/vxshare.ssdeep.clusters.49", "r") as f:
        for line in f.read().split("\n")[1:-1]:
            if line != "":
                counter += 1
                print(ppdeep.compare(h1, line))
                if ppdeep.compare(h1, line) != 0:
                    print("got here", ppdeep.compare(h1, line.split(",")[0]))


def search_79_file():
    global counter
    with open("ssdeep_datasets/vxshare.ssdeep.clusters.79", "r") as f:
        for line in f.read().split("\n")[1:-1]:
            if line != "":
                counter += 1
                print(ppdeep.compare(h1, line))
                if ppdeep.compare(h1, line) != 0:
                    print("got here", ppdeep.compare(h1, line.split(",")[0]))


if __name__ == '__main__':

    p1 = Process(target=search_49_file)
    p2 = Process(target=search_79_file)

    p1.start()
    p2.start()

    p1.join()
    p2.join()

    print(counter)
