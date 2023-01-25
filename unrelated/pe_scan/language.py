import pefile
import peid
import subprocess


def run_command(cmd):
    """
    runs cmd command in the command prompt and returns the output
    arg: cmd
    ret: the output of the command
    """
    return subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            shell=True,
                            stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE,
                            encoding="utf-8").communicate()


class Packers:

    @staticmethod
    def programming_language(path):

        allow_languages = ["Microsoft Visual C#", ".NET", "C++", "C#"]
        py_signature = ".py"

        if path.endswith(py_signature):
            return True

        packers = []
        a = run_command("peid " + path)[0]
        for i in a.split("\n")[:-1]:
            packers.append(i)

        result = any(any(language in s for s in packers) for language in allow_languages)
        return result


if __name__ == '__main__':
    print(Packers.programming_language("exe\\virus.exe"))