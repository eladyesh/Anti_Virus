import os

import psutil

if __name__ == '__main__':

    for process in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            process_info = process.as_dict(attrs=['pid', 'name', 'cmdline'])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        else:
            process_name = process_info['name']
            process_cmdline = process_info['cmdline']
            if process_name == "python.exe" and not any("delete_files.py" in element for element in process_cmdline):
                process.terminate()
                break

    def delete_file(path):
        if os.path.exists(path):
            os.remove(path)

    delete_file("virus.exe")
    # delete_file("Found_Virus")
    # delete_file(os.path.abspath(os.path.join(os.getcwd(), "..", "..") + "\LOG.txt"))
    # delete_file(os.path.abspath(os.path.join(os.getcwd(), "..", "..") + "\LOG_MEMORY.txt"))
    # delete_file(os.path.abspath(os.path.join(os.getcwd(), "..") + "\sys_internals\output_handles.txt"))