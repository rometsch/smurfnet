#!/usr/bin/env python3
import string
import unicodedata
import socket
import pickle
import argparse
import os
import json
import subprocess

HOST = 'localhost'

valid_filename_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
char_limit = 255


def appdir():
    appdir = os.path.join("/run/user", f"{os.getuid()}", "simdata")
    os.makedirs(appdir, exist_ok=True)
    return appdir


def main():

    options = parse_args()
    port = options.port
    if options.ping:
        print(ping_server(port))
    elif options.kill:
        kill_server(port)
    else:
        rec_data(options)


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

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Connect to server and send data
        port = 19998
        print("sending request to", HOST, port)
        sock.connect((HOST, port))
        sock.sendall(payload)

        received = sock.recv(4096)

        for n in range(1000):
            rec = sock.recv(16777216)
            if rec == b'':
                break
            received += rec

    return received


def get_simdata(simid, query, port):

    request = {
        "simid": simid,
        "query": query
    }
    variable = request
    # Pickle the object and send it to the server
    data_string = pickle.dumps(variable)

    received = send_request(data_string, port)

    answer = pickle.loads(received)

    if not isinstance(answer, dict):
        print(answer)
        raise RuntimeError(answer)

    rv = answer["data"]

    return rv


def rec_data(options):
    query = {
        "var": options.var,
        "N": options.N,
        "dim": options.dim,
        "planet": options.planet
    }

    simid = options.simid

    data = get_simdata(simid, query, options.port)

    print(f"Obtained data for {simid} at {query}")

    if options.outfile is not None:
        outfile = options.outfile
    else:
        outfile = f"data/{simid}/{dict_filename(query)}.pickle"
    os.makedirs(os.path.dirname(outfile), exist_ok=True)

    with open(outfile, "wb") as of:
        pickle.dump(data, of)


def kill_server(port):
    send_request("kill_server".encode(), port)


def ping_server(port):

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Connect to server and send data
        print("pinging server", HOST, port)
        sock.connect((HOST, port))
        sock.sendall("ping".encode())

        received = sock.recv(1024)

    rv = received.decode() == "ping"
    return rv


def get_open_port():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    s.listen(1)
    port = s.getsockname()[1]
    s.close()
    return port


def SSHTunnel(host, localport, remoteport):
    sshproc = subprocess.Popen(
        ["ssh", "-L", f"{localport}:localhost:{remoteport}", host])
    return sshproc


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--simid", type=str,
                        help="The id identifying the simulation.")
    parser.add_argument("--var", type=str,
                        help="Variable to get.")
    parser.add_argument("--N", type=int,
                        help="Output number.")
    parser.add_argument("--dim", type=int,
                        help="Data dimension.")
    parser.add_argument("--planet", type=int,
                        help="Number of planet.")
    parser.add_argument("-o", "--outfile",
                        help="Output file to store the data in.")
    parser.add_argument("-k", "--kill", action="store_true",
                        help="Kill the server.")
    parser.add_argument("--port", type=int, help="Server port", default=19998)
    parser.add_argument("--ping", action="store_true", help="Ping the server.")
    options = parser.parse_args()
    return options


if __name__ == "__main__":
    main()
