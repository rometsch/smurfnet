#!/usr/bin/env python3
import logging
import os
import socket
import pickle
import socketserver
import subprocess
import time
import traceback
import urllib
import json

from datetime import datetime

import diskcache
import disgrid
import smurf.search

from smurfnet.config import (Config, appdir)

from smurfnet.client import (ensure_server, get_hostname, get_hostport,
                                receive_data, make_request)

logger = logging.getLogger(__name__)

def parse_data_url(query_str):
    d = urllib.parse.parse_qs(query_str)
    d = {k: v[0] for k, v in d.items()}
    simid = d["simid"]
    del d["simid"]
    query = d
    return simid, query


def get_simulation_data(url):
    req = urllib.parse.urlparse(url)
    simid, query = parse_data_url(req.query)

    searchres = smurf.search.search_local_cache(simid)
    if len(searchres) > 0:
        # have simulation locally
        rv = get_data_local(url)
    else:
        # try another server
        rv = get_data_relay(simid, url)

    return rv


def get_data_local(url):
    logger.debug(f"Obtaining local disgrid data with url '{url}'")
    req = urllib.parse.urlparse(url)
    to_update = req.fragment == "update"


    simid, query = parse_data_url(req.query)

    logger.debug(
        f"Handling simid='{simid}' with action '{req.path}' and query '{query}'")

    d = disgrid.SData(simid, search_remote=False, update=to_update)

    if req.path.startswith("/get"):
        query_dict = query.copy()
        for key, val in query_dict.items():
            if val == "None":
                query_dict[key] = None
        data = d.get(**query_dict)
    elif req.path.startswith("/avail"):
        data = d.avail()
    else:
        data = url

    rv = {
        "simid": simid,
        "url": url,
        "data": data
    }
    return rv


def get_data_relay(simid, url):
    hostname = get_hostname(simid)
    port = get_hostport(hostname)
    logger.info(
        f"Using relay ('{hostname}' on port '{port}') to obtain data for simid '{simid}' with query '{url}'")

    try:
        data = receive_data(url, port)
    except (ConnectionRefusedError, ConnectionResetError, ConnectionRefusedError):
        if hostname is not None:
            port = ensure_server(hostname)
            data = receive_data(url, port)

    ddict = {
        "simid": simid,
        "url": url,
        "data": data,
        "meta": {
            "origin": hostname,
            "port": port
        }
    }
    return ddict


def relay_request(url, relay):
    logger.info(
        f"Using relay '{relay}' for  query '{url}'")
    s = list(urllib.parse.urlsplit(url))
    s[1] = relay
    url = urllib.parse.urlunsplit(s)
    rv = make_request(url, raw=True)
    return rv

def remove_fragment(url):
    p = urllib.parse.urlparse(url)
    rv = p._replace(fragment="").geturl()
    return rv

class MyTCPHandler(socketserver.BaseRequestHandler):
    """
    The request handler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def __init__(self, *args, **kwargs):
        try:
            self.config = Config()


            try:
                conf = Config()
                cachedir = conf["cache_dir"]
                self.cache = diskcache.Cache(directory=cachedir)
            except Exception as e:
                self.cache = None
                logger.info(f"Running without cache because {e}")


            super().__init__(*args, **kwargs)
        except Exception as e:
            logger.error(f"Exception {e}")
            raise


    def handle(self):

        # self.request is the TCP socket connected to the client
        try:
            url = self.request.recv(4096).decode("utf-8")
            logger.info("REQUEST: {} wrote:".format(self.client_address[0]))
            logger.info(f"REQUEST: {url}")
            self.url_cmps = urllib.parse.urlparse(url)
            scheme = self.url_cmps.scheme
            query = urllib.parse.parse_qs(self.url_cmps.query)
            update_cache = self.url_cmps.fragment == "update"

            logger.debug(f"Url parsed to {self.url_cmps}")
            logger.debug(f"Url parsed to query {query}")
            logger.debug(f"Caching is {'disabled' if update_cache else 'enabled'}")

            if scheme == "simnet":
                self.handle_simnet()

            else:
                if not update_cache and self.cache is not None and url in self.cache:
                    logger.info(f"Using cached result for '{url}'")
                    answer = self.cache[url]
                elif "relay" in self.config.data:
                    relay = self.config.data["relay"]
                    logger.info(f"Relaying request to host '{relay}'")
                    answer = relay_request(url, relay)
                elif scheme == "disgrid":
                    answer = handle_disgrid(url)
                elif scheme == "smurf":
                    answer = handle_smurf(url)
                else:
                    answer = pickle.dumps(f"Scheme '{scheme}' not supported by smurfnet on server '{socket.gethostname()}'.")
                
                if self.cache is not None:
                    self.cache[remove_fragment(url)] = answer

                self.request.send(answer)

        except Exception as e:
            logger.info(
                f"REQUEST: Exception while handling request: {traceback.format_exc()}")
            answer = "{}".format(traceback.format_exc())
            answer = answer.splitlines()
            hostname = socket.gethostname()
            rv = []
            for line in answer:
                rv.append(f"{hostname} : {line}")
            rv = f"{hostname} : exception occurred at {datetime.now()}: \n" + "\n".join(rv)
            self.request.sendall(pickle.dumps(rv))

    def handle_simnet(self):
        path = self.url_cmps.path
        if path.startswith("/kill"):
            logger.info("Shutting down server...")
            self.server.shutdown()
            return
        elif path.startswith("/ping"):
            logger.info("REQUEST: received ping, pinning back...")
            self.request.send("ping".encode())
            return
        elif path.startswith("/restart"):
            restart_wrapped()


def handle_disgrid(url):
    logger.info("REQUEST: Loading simulation data...")
    ddict = get_simulation_data(url)
    payload = pickle.dumps(ddict)
    return payload


def handle_smurf(url):
    cmps = urllib.parse.urlparse(url)
    path = cmps.path
    d = urllib.parse.parse_qs(cmps.query)
    try:
        d["pattern"]
        if d["pattern"] == "":
            d["pattern"] = cmps.path.split("/")[-1]
    except KeyError:
        d["pattern"] = cmps.path.split("/")[-1]

    logging.debug(f"Smurf request with url {url}, cmps {cmps}, d {d}")

    if path.startswith("/search"):
        logger.info(f"Smurf search")
        rv = smurf.search.search(d["pattern"])
        logger.debug(f"Found {len(rv)} results")

    elif path.startswith("/verify"):
        logger.info(f"Smurf verify")
        rv = smurf.search.search(d["pattern"], ensure_exist=True)
        logger.debug(f"Found {len(rv)} results")
    else:
        rv = {}

    return json.dumps(rv).encode("utf-8")


def get_open_port():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    s.listen(1)
    port = s.getsockname()[1]
    s.close()
    return port


def write_port(port):
    portfile = os.path.join(appdir(), "localhost.port")
    with open(portfile, "w") as outfile:
        print(f"{port}", file=outfile)


def write_pid():
    pidfile = os.path.join(appdir(), "pid")
    pid = os.getpid()
    with open(pidfile, "w") as outfile:
        print(f"{pid}", file=outfile)


def read_port():
    filename = os.path.join(appdir(), "localhost.port")
    try:
        with open(filename, "r") as infile:
            rv = int(infile.read().strip())
    except (FileNotFoundError, ValueError):
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
    """ Start the server in this process and server forever.
    This function should not be called manually. Use launch_server instead.
    
    Parameters
    ----------
    host: str
        Interface to server on.
    port: int
        Port number to server on.
    """

    if port < 0:
        port = get_open_port()

    logger.info("-"*40)
    logger.info(
        f"Starting server process on host {host} on port {port} with pid {os.getpid()}")
    socketserver.TCPServer.allow_reuse_address = True
    # Create the server, binding to 'host' on port 'port'

    write_port(port)
    write_pid()

    try:
        with ThreadedTCPServer((host, port), MyTCPHandler) as server:
            # Activate the server; this will keep running until you
            # interrupt the program with Ctrl-C
            logger.debug("Now servering...")
            server.serve_forever()
    except Exception as e:
        logger.error(f"Received {e}")
        raise

def launch_server(host, port):
    port = decide_port(port)
    write_port(-1)
    cmd = [os.path.expanduser("~/.local/bin/smurfnet"),
           "server", "--host", host, "--port", f"{port}", "--start"]

    subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    for _ in range(1000):
        time.sleep(0.001)
        port = read_port()
        if port > 0:
            print(port)
            break


def restart_wrapped():
    cmd = [os.path.expanduser("~/.local/bin/smurfnet"),
           "server", "--restart"]

    subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def decide_port(port):
    if port is None or port <= 0:
        # check config file for port
        config = Config()
        try:
            port = int(config["port"])
        except (KeyError, TypeError):
            # attempt to read the port
            port = read_port()
    if port is None or port <= 0:
        # no portfile
        port = get_open_port()
    return port

def restart(host, port):
    logger.info("Restarting server")
    port = decide_port(port)
    if check_running():
        pid = read_pid()
        logger.info(f"Killing old server with pid {pid}")
        os.kill(pid, 15)
    launch_server(host, port)


def server(options):

    logging.basicConfig(filename=os.path.join(appdir(), "server.log"),
                        filemode='a',
                        level=logging.DEBUG,
                        format=socket.gethostname() + ' : %(asctime)s - %(name)s - %(levelname)s - %(message)s')

    if options.start:
        # definitely start a server
        start_server(options.host, options.port)

    elif options.restart:
        restart(options.host, options.port)

    else:
        if (check_running() and read_port() > 0) and (options.port == -1 or options.port == read_port()):
            # if a server is running and the port matches the running server's port, use it
            port = read_port()
            logger.info(f"Reporting existing server running on port {port}.")
            print(port)
        else:
            # otherwise launch a new server with this port
            logger.info("Launching a new server.")
            launch_server(options.host, options.port)
