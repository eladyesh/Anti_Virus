import os
import time
from multiprocessing import Queue, Process
from threading import Thread
import ppdeep
import concurrent.futures
import itertools
from queue import Queue

# h1 = ppdeep.hash_from_file("nop.exe")
# h2 = ppdeep.hash_from_file("virus.exe")
# print(ppdeep.compare(h1, h2))
from PyQt5.QtCore import QObject, pyqtSignal

counter = 0
scan_counter = 0
changed_counter = False


def process_chunk(hash, chunk):
    """
    Process a chunk of lines and compare each line with the given hash.

    Args:
        hash (str): The hash to compare the lines with.
        chunk (list): The chunk of lines to process.

    """
    global counter, changed_counter, scan_counter
    for line in chunk:
        if line != "":
            # print(ppdeep.compare(hash, line))
            scan_counter += 1
            if ppdeep.compare(hash, line) != 0:
                # print("got here", ppdeep.compare(hash, line.split(",")[0]))
                counter += 1
                changed_counter = True
        time.sleep(0.1)


def search_49_file(hash, stop_thread):
    """
    Search for the given hash in the file "vxshare.ssdeep.clusters.49".
    searching within the files that have 49% percent chance to match malicious files

    Args:
        hash (str): The hash to search for.
        stop_thread (bool): Flag to stop the thread.

    """
    global counter
    with concurrent.futures.ThreadPoolExecutor() as executor:
        with open(os.path.abspath("vxshare-clusters-49/vxshare.ssdeep.clusters.49").replace("graphics",
                                                                                            "fuzzy_hashing")) as f:
            chunk_size = 1000
            for lines in iter(lambda: list(itertools.islice(f, chunk_size)), []):
                if not stop_thread:
                    executor.submit(process_chunk, hash, lines)
                time.sleep(0.1)


def search_79_file(hash, stop_thread):
    """
    Search for the given hash in the file "vxshare.ssdeep.clusters.79".
    searching within the files that have 79% percent chance to match malicious files

    Args:
        hash (str): The hash to search for.
        stop_thread (bool): Flag to stop the thread.

    """
    global counter
    with concurrent.futures.ThreadPoolExecutor() as executor:
        with open(os.path.abspath("vxshare-clusters-79/vxshare.ssdeep.clusters.79").replace("graphics",
                                                                                            "fuzzy_hashing")) as f:
            chunk_size = 1000
            for lines in iter(lambda: list(itertools.islice(f, chunk_size)), []):
                if not stop_thread:
                    executor.submit(process_chunk, hash, lines)
                time.sleep(0.1)


class my_label_object(QObject):
    """
    Custom QObject class emitting a signal for label change.
    """

    label_change = pyqtSignal(str)

    def __init__(self):
        super().__init__()

    def invoke(self, message):
        """
        Emits the label_change signal with the given message.

        Args:
            message (str): The message to be emitted.

        Returns:
            None
        """
        self.label_change.emit(message)


def change_fuzzy_label(label, label_object, stop_thread):
    """
    Continuously updates the label with the number of scanned fuzzy hashes.

    Args:
        label (QLabel): The label to be updated.
        label_object (MyLabelObject): The custom QObject instance to emit the signal.
        stop_thread (bool): Flag to stop the thread execution.

    Returns:
        None
    """

    while True:
        if label and not stop_thread:
            # label.setText(f"Scanned {scan_counter} / 47544373 fuzzy hashes")
            label_object.invoke(f"Scanned {scan_counter} / 47544373 fuzzy hashes")

        time.sleep(0.1)


def num_of_lines():
    """
    Counts the total number of lines in two specific files.

    Returns:
        int: The total number of lines.
    """
    # Open the file in read mode
    with open(r"D:\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated\fuzzy_hashing\vxshare-clusters"
              r"-49\vxshare.ssdeep.clusters.49", "r") as f:
        counter_49 = sum(1 for line in f if line.strip())

    # Open the file in read mode
    with open(r"D:\Cyber\YB_CYBER\project\FinalProject\poc_start\poc_start\unrelated\fuzzy_hashing\vxshare-clusters"
              r"-79\vxshare.ssdeep.clusters.79", "r") as f:
        counter_79 = sum(1 for line in f if line.strip())

    return counter_49 + counter_79


class my_spin_object(QObject):
    """
    Custom QObject class emitting a signal for spin counter change.
    """
    spin_change = pyqtSignal(int)

    def __init__(self):
        super().__init__()

    def invoke(self, number):
        """
        Emits the spin_change signal with the given number.

        Args:
            number (int): The number to be emitted.

        Returns:
            None
        """
        self.spin_change.emit(number)


def change_spin_counter(spin_box, redis_base, md5_hash, spin_object, stop_thread):
    """
    Continuously updates the spin box counter and Redis base with the number of fuzzy hashes found.

    Args:
        spin_box (QSpinBox): The spin box widget to update.
        redis_base (Redis): The Redis client instance.
        md5_hash (str): The MD5 hash.
        spin_object (MySpinObject): The custom QObject instance to emit the signal.
        stop_thread (bool): Flag to stop the thread execution.

    Returns:
        None
    """
    while True:

        if not stop_thread:
            # spin_box.setValue(counter)
            spin_object.invoke(counter)
            redis_base.hset(md5_hash, "num_of_fuzzy_found", counter)
            # redis_base.print_key(md5_hash, "num_of_fuzzy_found", False)
            time.sleep(5)


if __name__ == '__main__':
    print(num_of_lines())
