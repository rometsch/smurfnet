#!/usr/bin/env python3
from client import ensure_server, get_hostname, get_hostport, get_simdata
import argparse
import pickle
import socketserver
import simdata
import os
import time
import traceback

import subprocess

import logging
import smurf.search


def appdir():
    appdir = os.path.join("/run/user", f"{os.getuid()}", "simdata")
    os.makedirs(appdir, exist_ok=True)
    return appdir


logging.basicConfig(filename=os.path.join(appdir(), "server.log"),
                    filemode='a',
                    level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(message)s')


def get_simulation_data(simid, query):
    searchres = smurf.search.search_local_cache(simid)
    if len(searchres) > 0:
        # have simulation locally
        rv = get_data_local(simid, query)
    else:
        # try another server
        rv = get_data_relay(simid, query)
    return rv


def get_data_local(simid, query):
    query_dict = query
    print(query_dict)
    d = simdata.SData(simid)

    rv = {
        "simid": simid,
        "query": query,
        "data": d.get(**query_dict)
    }
    return rv


def get_data_relay(simid, query):
    hostname = get_hostname(simid)
    port = get_hostport(hostname)
    logging.info(
        f"Using relay ('{hostname}' on port '{port}') to obtain data for simid '{simid}' with query '{query}'")

    try:
        data = get_simdata(simid, query, port)
    except (ConnectionRefusedError, ConnectionResetError, ConnectionRefusedError):
        if hostname is not None:
            port = ensure_server(hostname)
            data = get_simdata(simid, query, port)

    ddict = {
        "simid": simid,
        "query": query,
        "data": data,
        "meta": {
            "origin": hostname,
            "port": port
        }
    }
    return ddict


class MyTCPHandler(socketserver.BaseRequestHandler):
    """
    The request handler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def handle(self):

        # self.request is the TCP socket connected to the client
        try:
            self.data = self.request.recv(4096)

            try:
                plain_text = self.data.decode()
                if plain_text == "kill_server":
                    logging.info("Shutting down server...")
                    self.server.shutdown()
                    return
                elif plain_text == "ping":
                    logging.info("REQUEST: received ping, pinning back...")
                    self.request.send("ping".encode())
                    return
            except (AttributeError, UnicodeDecodeError):
                pass

            request = pickle.loads(self.data)
            logging.info("REQUEST: {} wrote:".format(self.client_address[0]))
            logging.info(f"REQUEST: {request}")

            simid = request["simid"]
            query = request["query"]

            logging.info("REQUEST: Loading simulation data...")
            ddict = get_simulation_data(simid, query)
            payload = pickle.dumps(ddict)

            # answer = request
            logging.info(
                f"REQUEST: Sending simulation data for {simid} with query: {query}")

            self.request.send(payload)
        except Exception as e:
            logging.info(
                f"REQUEST: Exception while loading data: {traceback.format_exc()}")
            self.request.sendall(pickle.dumps(
                "{}".format(traceback.format_exc())))


def get_open_port():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    s.listen(1)
    port = s.getsockname()[1]
    s.close()
    return port


def write_port(port):
    portfile = os.path.join(appdir(), "port")
    with open(portfile, "w") as outfile:
        print(f"{port}", file=outfile)


def write_pid():
    pidfile = os.path.join(appdir(), "pid")
    pid = os.getpid()
    with open(pidfile, "w") as outfile:
        print(f"{pid}", file=outfile)


def read_port():
    filename = os.path.join(appdir(), "port")
    try:
        with open(filename, "r") as infile:
            rv = int(infile.read().strip())
    except FileNotFoundError:
        rv = -1
    return rv


def read_pid():
    filename = os.path.join(appdir(), "pid")
    try:
        with open(filename, "r") as infile:
            rv = int(infile.read().strip())
    except FileNotFoundError:
        rv = -1
    return rv


def check_pid(pid):
    """ Check For the existence of a unix pid. """
    try:
        os.kill(pid, 0)
    except OSError as e:
        return False
    else:
        return True


def check_running():
    pid = read_pid()
    return check_pid(pid)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


def start_server(host, port):

    if port < 0:
        port = get_open_port()

    logging.info("-"*40)
    logging.info(
        f"Starting server process on host {host} on port {port} with pid {os.getpid()}")
    socketserver.TCPServer.allow_reuse_address = True
    # Create the server, binding to 'host' on port 'port'

    write_port(port)
    write_pid()

    with ThreadedTCPServer((host, port), MyTCPHandler) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever()


def launch_server(host, port):
    if port <= 0:
        port = get_open_port()

    write_port(-1)
    subprocess.Popen(["python3", __file__, "--host", host, "--port", f"{port}", "--start"],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)

    for _ in range(1000):
        time.sleep(0.001)
        port = read_port()
        if port > 0:
            print(port)
            break


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", type=str, default="localhost",
                        help="Server address")
    parser.add_argument("--port", type=int, default=-1,
                        help="Server port")
    parser.add_argument("--start", action="store_true")
    parser.add_argument("--restart", action="store_true")
    options = parser.parse_args()

    if options.start:
        # definitely start a server
        start_server(options.host, options.port)

    elif options.restart:
        logging.info("Restarting server")
        if check_running():
            pid = read_pid()
            logging.info(f"Killing old server with pid {pid}")
            os.kill(pid, 15)
        if options.port == -1:
            # reuse old port if none is provided
            port = read_port()
        else:
            port = options.port
        launch_server(options.host, port)

    else:
        if (check_running() and read_port() > 0) and (options.port == -1 or options.port == read_port()):
            # if a server is running and the port matches the running server's port, use it
            port = read_port()
            logging.info(f"Reporting existing server running on port {port}.")
            print(port)
        else:
            # otherwise launch a new server with this port
            logging.info("Launching a new server.")
            launch_server(options.host, options.port)
