#!/usr/bin/env python3
import socket
import pickle
import argparse
import os

HOST = 'localhost'
PORT = 9998


def get_2d_data(simid, Noutput):
    try:
        from server import PORT as SERVER_PORT
    except ImportError:
        SERVER_PORT = PORT
    port = SERVER_PORT
    # Create an instance of ProcessData() to send to server.
    request = {
        "simid": simid,
        "Noutput": Noutput
    }
    variable = request
    # Pickle the object and send it to the server
    data_string = pickle.dumps(variable)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Connect to server and send data
        sock.connect((HOST, port))
        sock.sendall(data_string)

        received = sock.recv(4096)
        
        for n in range(1000):
            rec = sock.recv(16777216)
            if rec == b'':
                break
            received += rec

    answer = pickle.loads(received)

    if not isinstance(answer, dict):
        raise RuntimeError(answer)

    return answer


def main():
    options = parse_args()

    simid = options.simid
    Noutput = options.Noutput

    data = get_2d_data(simid, Noutput)

    print(f"Obtained data for {simid} at {Noutput}")

    if options.outfile is not None:
        outfile = options.outfile
    else:
        outfile = f"data/{simid}/{Noutput}.pickle"
    os.makedirs(os.path.dirname(outfile), exist_ok=True)

    with open(outfile, "wb") as of:
        pickle.dump(data, of)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("simid", type=str,
                        help="The id identifying the simulation.")
    parser.add_argument("Noutput", type=int,
                        help="Output number to get data for.")
    parser.add_argument("-o", "--outfile",
                        help="Output file to store the data in.")
    options = parser.parse_args()
    return options


if __name__ == "__main__":
    main()
