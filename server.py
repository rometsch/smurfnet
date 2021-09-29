#!/usr/bin/env python3
import argparse
import pickle
import socketserver
import simdata
import threading


def serialize_simdata_2d(simid, query):
    query_dict = query
    print(query_dict)
    d = simdata.SData(simid)

    rv = {
        "simid": simid,
        "query": query,
        "data": d.get(**query_dict)
    }
    return rv


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
                if self.data.decode() == "kill_server":
                    print("Shutting down server...")
                    self.server.shutdown()
                    return
            except (AttributeError, UnicodeDecodeError):
                pass

            request = pickle.loads(self.data)
            print("{} wrote:".format(self.client_address[0]))
            print(request)

            print("Getting simulation data")
            simid = request["simid"]
            query = request["query"]
            ddict = serialize_simdata_2d(simid, query)
            payload = pickle.dumps(ddict)

            # answer = request
            print(f"Sending simulation data for {simid} with query: {query}")

            self.request.send(payload)
        except Exception as e:
            raise
            # print(e)
            # self.request.sendall(pickle.dumps(str(e)))


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = "localhost", 9998

    socketserver.TCPServer.allow_reuse_address = True
    # Create the server, binding to localhost on port 9999
    with ThreadedTCPServer((HOST, PORT), MyTCPHandler) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever()
