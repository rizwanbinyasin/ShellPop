from setuptools import setup
from setuptools.command.install import install
from subprocess import Popen, PIPE
import os

def applyChanges():
    # Running "source ~/.bashrc" in a subprocess does NOTHING to the current shell.
    # But to keep original behavior, we leave it.
    proc = Popen("bash -c 'source ~/.bashrc'", stdout=PIPE, stderr=PIPE, shell=True)
    proc.communicate()
    return None


def activateTabComplete():
    proc = Popen("activate-global-python-argcomplete",
                 stdout=PIPE, stderr=PIPE, shell=True)
    proc.communicate()
    return proc.poll() == 0  # FIXED: "is 0" → "== 0"


def autoComplete():
    """
    Get the content required to register Shellpop into tab auto-completion
    @zc00l
    """
    proc = Popen("register-python-argcomplete shellpop",
                 stdout=PIPE, stderr=PIPE, shell=True)
    stdout, _ = proc.communicate()

    # stdout is bytes in Python 3 → decode to string
    return stdout.decode("utf-8")


class CustomInstall(install):
    def run(self):
        super().run()

        bashrc_file = os.path.join(os.environ["HOME"], ".bashrc")

        if not os.path.exists(bashrc_file):
            return None

        with open(bashrc_file, "r") as f:
            bashrc_content = f.read()

        if "shellpop" not in bashrc_content:
            print("Registering shellpop in .bashrc for auto-completion ...")

            activateTabComplete()

            # Append auto-complete script to .bashrc
            with open(bashrc_file, "a") as f:
                f.write("\n{}\n".format(autoComplete()))

            print("Auto-completion has been installed.")
            applyChanges()


setup(
    name='shellpop',
    version='0.3.6',
    description='Bind and Reverse shell code generator to aid Penetration Tester in their work. Originally dev by authors (zc00l, lowfuel, touhidshaikh) in python2; forked and updated by rizwanbinyasin in python3',
    url='https://github.com/rizwanbinyasin/ShellPop.git',
    author='rizwanbinyasin',
    author_email='rizwanbinyasin@gmail.com',
    license='MIT',
    packages=['shellpop'],
    package_dir={"shellpop": "src"},
    package_data={"shellpop": ["src/*"]},
    scripts=["bin/shellpop"],
    zip_safe=False,
    cmdclass={'install': CustomInstall}
)
