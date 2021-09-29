#!/usr/bin/env python3
import string
import unicodedata
import socket
import pickle
import argparse
import os
import json

HOST = 'localhost'
PORT = 19998


valid_filename_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
char_limit = 255


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


def send_request(payload):
    port = PORT
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Connect to server and send data
        port = 19998
        print(HOST, port)
        sock.connect((HOST, port))
        sock.sendall(payload)

        received = sock.recv(4096)

        for n in range(1000):
            rec = sock.recv(16777216)
            if rec == b'':
                break
            received += rec

    return received

def get_2d_data(simid, query):

    request = {
        "simid": simid,
        "query": query
    }
    variable = request
    # Pickle the object and send it to the server
    data_string = pickle.dumps(variable)

    received = send_request(data_string)

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

    data = get_2d_data(simid, query)

    print(f"Obtained data for {simid} at {query}")

    if options.outfile is not None:
        outfile = options.outfile
    else:
        outfile = f"data/{simid}/{dict_filename(query)}.pickle"
    os.makedirs(os.path.dirname(outfile), exist_ok=True)

    with open(outfile, "wb") as of:
        pickle.dump(data, of)

def kill_server():
    send_request("kill_server".encode())

def main():

    options = parse_args()
    if options.kill:
        kill_server()
    else:
        rec_data(options)

    


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
    options = parser.parse_args()
    return options


if __name__ == "__main__":
    main()
