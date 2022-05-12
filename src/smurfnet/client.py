#!/usr/bin/env python3
import string
import unicodedata
import socket
import pickle
import os
import json
import subprocess
import smurf.search
import logging
import sys
import time
import urllib

from smurfnet.auth import ensure_key
from smurfnet.config import appdir

HOST = 'localhost'

valid_filename_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
char_limit = 255


logging.basicConfig(filename=os.path.join(appdir(), "simdata.log"),
                    filemode='a',
                    level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

logger = logging.getLogger(__name__)


def client(options):

    if options.v:
        stdout_handler = logging.StreamHandler(sys.stdout)
        logger.addHandler(stdout_handler)

    if options.host is not None:
        hostname = options.host
        port = get_hostport(hostname)
        if port <= 0:
            port = ensure_server(hostname)
        options.port = port
    elif options.port > 0:
        hostname = None
        port = options.port
    else:
        cmp = urllib.parse.urlparse(options.url)
        hostname = cmp.hostname
        port = get_hostport(hostname)
        options.port = port

    try:
        handle_options(options, port)
    except (ConnectionRefusedError, ConnectionResetError, ConnectionRefusedError):
        if hostname is not None:
            port = ensure_server(hostname)
            handle_options(options, port)


def handle_options(options, port):

    if options.url:
        print(make_request(options.url))
    elif options.ping:
        print(ping_server(port))
    elif options.kill:
        kill_server(port)
    elif options.restart:
        restart_server(port)


def make_request(url):
    req = urllib.parse.urlparse(url)
    hostname = req.hostname

    logger.debug(f"Received request '{url}'")

    port = get_hostport(hostname)
    if port <= 0:
        port = ensure_server(hostname)

    try:
        rv = receive_data(url, port)
    except (ConnectionRefusedError, ConnectionResetError, ConnectionRefusedError):
        if hostname is not None:
            port = ensure_server(hostname)
            rv = receive_data(url, port)

    return rv


def ensure_server(hostname):
    logger.debug(f"Ensure a server runs on '{hostname}'")
    oldport = read_portfile(hostname)

    if oldport == 0 or not ping_server(int(oldport)):
        port = start_server_remote(hostname)
        write_portfile(hostname, port)
    else:
        port = oldport
    return int(port)


def get_hostname(simid):
    logger.info(f"Looking up hostname for simid '{simid}'")
    siminfo = smurf.search.search(simid)[0]
    return siminfo["host"]


def read_portfile(hostname):
    if hostname == "127.0.0.1":
        hostname = "localhost"
    portfile = os.path.join(appdir(), f"{hostname}.port")
    try:
        with open(portfile, "r") as infile:
            rv = int(infile.read().strip())
    except (FileNotFoundError, ValueError):
        rv = 0
    logger.debug(f"Found port '{rv}' for server on '{hostname}'")
    return rv


def write_portfile(hostname, port):
    logger.info(f"Saving port '{port}' for host '{hostname}'")
    portfile = os.path.join(appdir(), f"{hostname}.port")
    with open(portfile, "w") as outfile:
        print(port, file=outfile)


def get_hostport(hostname):
    oldport = read_portfile(hostname)
    return int(oldport)


def start_server_remote(hostname):
    logger.info(f"Starting a server on host '{hostname}'")
    cmd = []
    if hostname != "localhost":
        cmd = ["ssh", hostname]
    cmd, env = wrap_ssh_cmd(hostname, cmd)
    cmd += [".local/bin/smurfnet", "server"]
    logging.debug(cmd)
    res = subprocess.run(cmd, stdout=subprocess.PIPE, env=env,
                         stderr=subprocess.PIPE, cwd=os.path.expanduser("~"))
    remoteport = res.stdout.decode().strip()
    if res.returncode != 0:
        logger.error(
            f"Received non-zero return code from server start on '{hostname}'")
        logger.error(res.stderr.decode().strip())
        raise RuntimeError(f"Could not start server on '{hostname}'")
    logger.info(f"Server runs on port '{remoteport}' on host '{hostname}'")

    if hostname != "localhost":
        localport = get_open_port()
        SSHTunnel(hostname, localport, remoteport)
    else:
        localport = remoteport
    return localport


def clean_filename(filename, whitelist=valid_filename_chars, replace=' '):
    # replace spaces
    for r in replace:
        filename = filename.replace(r, '_')

    # keep only valid ascii chars
    cleaned_filename = unicodedata.normalize(
        'NFKD', filename).encode('ASCII', 'ignore').decode()

    # keep only whitelisted chars
    cleaned_filename = ''.join(c for c in cleaned_filename if c in whitelist)
    if len(cleaned_filename) > char_limit:
        print("Warning, filename truncated because it was over {}. Filenames may no longer be unique".format(char_limit))
    return cleaned_filename[:char_limit]


def dict_filename(d):
    """ Create a filename out of the entries of a dict.

    Remove entries that are None.

    Parameters
    ----------
    d : dict
        Dict to be parsed.

    Returns
    -------
    str
        String safe for use as a filename.
    """
    cd = d.copy()
    for key in [k for k in cd.keys()]:
        if cd[key] is None:
            del cd[key]
    rv = json.dumps(cd)
    rv = clean_filename(rv)
    return rv


def send_request(payload, port):
    logger.debug(f"Sending payload to host '{HOST}' on port '{port}'")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Connect to server and send data
        sock.connect((HOST, port))
        sock.sendall(payload)

        logger.debug(
            f"Receiving payload from host '{HOST}' on port '{port}'...")

        received = sock.recv(4096)

        for n in range(1000):
            rec = sock.recv(16777216)
            if rec == b'':
                break
            received += rec

        logger.debug(
            f"Finished receiving payload from host '{HOST}' on port '{port}'.")

    return received


def receive_data(url, port):
    logger.debug(f"Obtaining '{url}' on port '{port}'")

    received = send_request(url.encode("utf-8"), port)

    try:
        rv = received.decode()
    except UnicodeDecodeError:
        answer = pickle.loads(received)

        if not isinstance(answer, dict):
            print(answer)
            raise RuntimeError(answer)

        rv = answer["data"]

    return rv


def kill_server(port):
    logger.info(f"Sending kill command to server on port '{port}'")
    send_request("simnet://localhost/kill".encode(), port)


def restart_server(port):
    logger.info(f"Sending restart command to server on port '{port}'")
    send_request("simnet://localhost/restart".encode(), port)


def ping_server(port):
    host = HOST
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # Connect to server and send data
            logger.info(f"Pinging server '{host}' on port {port}")
            sock.connect((HOST, port))
            sock.sendall("simnet://localhost/ping".encode())

            received = sock.recv(1028)
            logger.debug("Received ping")

        rv = received.decode() == "ping"
    except (ConnectionRefusedError, ConnectionResetError) as e:
        logger.warning(f"Received '{e}' from pinning port {port}")
        rv = False

    logger.info(f"Ping successful? {rv}")

    return rv


def get_open_port():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    s.listen(1)
    port = s.getsockname()[1]
    s.close()
    return port

def wrap_ssh_cmd(hostname, cmd):
    logger.debug(f"Getting key path for host '{hostname}'")
    key_path = ensure_key(hostname)
    env = {}
    if os.path.exists(key_path):
        logger.debug(f"Key exists, using it.")
        cmd += ["-i", key_path, "-S", "none"]
        env["SSH_AUTH_SOCK"] = ""
    return cmd, env
    

def SSHTunnel(hostname, localport, remoteport):
    logger.info(
        f"Setting up ssh tunnel from local port '{localport}' to host '{hostname}' port '{remoteport}'")
    cmd = ["ssh", "-f", "-N", "-L",
           f"{localport}:localhost:{remoteport}", hostname]
    cmd, env = wrap_ssh_cmd(hostname, cmd)
    
    sshproc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
    time.sleep(0.1)
    return sshproc
