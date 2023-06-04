import os

import pefile
import peid
import subprocess


def run_command(cmd):
    """
    Runs a command in the command prompt and returns the output.

    Args:
        cmd (str): The command to be executed.

    Returns:
        str: The output of the command.
    """
    return subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            shell=True,
                            stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE,
                            encoding="utf-8").communicate()


class Packers:

    @staticmethod
    def programming_language(path):
        """
        Determine the programming language used in a given executable file.

        Args:
            path (str): The path to the executable file.

        Returns:
            str: The programming language detected or "py" if the file size exceeds 6000 KB.
        """
        allow_languages = ["Microsoft Visual C#", ".NET", "C++", "C#"]

        if os.path.getsize(path) > 6000 * 1024:
            return "py"

        if os.path.getsize(path) < 8 * 1024 and os.path.getsize(path) > 7 * 1024:
            return True

        packers = []
        a = run_command("peid " + path)[0]

        for i in a.split("\n")[:-1]:
            packers.append(i)

        result = any(any(language in s for s in packers) for language in allow_languages)
        return result


if __name__ == '__main__':
    print(Packers.programming_language(os.path.abspath("exe\\c#_virus.exe")))