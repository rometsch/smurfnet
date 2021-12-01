#!/usr/bin/env python3
import os
from subprocess import run

def main():
    command = ""

    while command != "exit":
        if command == "log":
            try:
                run(["tail", "-f", f"/run/user/{os.geteuid()}/simdata/simdata.log"])
            except KeyboardInterrupt:
                print("")
        print("Type 'log' to follow the log (then Ctrl-c to stop):")
        command = input("Type 'exit' to close the connection: ")

if __name__=="__main__":
    main()