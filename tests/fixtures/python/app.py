import subprocess


def run(cmd):
    unused = 1
    subprocess.call(cmd, shell=True)
