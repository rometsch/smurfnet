#!/usr/bin/env python3
import os
from subprocess import run

def call_server():
    run([os.path.expanduser("~/.local/bin/smurfnet"), "server"])

def restart_server():
    run([os.path.expanduser("~/.local/bin/smurfnet"), "server", "--restart"])

def view_log():
    try:
        run(["tail", "-f", f"/run/user/{os.geteuid()}/smurfnet/log"])
    except KeyboardInterrupt:
        pass

def show_sshcmd():
    try:
        print(os.environ["SSH_ORIGINAL_COMMAND"].strip())
    except KeyError:
        pass

def help():
    print("Type 'log' to follow the log (then Ctrl-c to stop):")
    print("Type 'server' to start a server and return the port:")
    print("Type 'restart' to restart the server and return the port:")
    print("Type 'sshcmd' to view the command passed to the ssh shell.")
    print("Type 'exit' to close the connection: ")

def main():
    try:
        cmd = os.environ["SSH_ORIGINAL_COMMAND"].strip()
        if cmd == ".local/bin/smurfnet server":
            call_server()
            exit(0)
        elif cmd == ".local/bin/smurfnet server --restart":
            restart_server()
            exit(0)
    except KeyError:
        pass            
    command = ""

    while command != "exit":
        if command == "log":
            view_log()
        elif command == "server":
            call_server()
        elif command == "restart":
            restart_server()
        elif command == "sshcmd":
            show_sshcmd()
        elif command == "help":
            help()
        command = input("[smurfnet]> ")

if __name__=="__main__":
    main()