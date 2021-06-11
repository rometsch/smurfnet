import pickle
import socketserver
import simdata

PORT = 9998

def serialize_simdata_2d(simid, Noutput):
    d = simdata.SData(simid)
    rv = {"Nfinal" : len(d.fluids["gas"].get_time("2d", "mass density"))-1}
    for key in ["mass density", "energy density", "velocity radial", "velocity azimuthal", "pressure"]:
        try:
            field = d.fluids["gas"].get("2d", key, Noutput)
        except KeyError as e:
            pass
        rv[key] = {
            "Noutput" : Noutput,
            "time" : field.time.cgs.value,
            "units" : "cgs",
            "name" : field.name,
            "r" : field.grid.get_coordinates("r").cgs.value,
            "phi" : field.grid.get_coordinates("phi").cgs.value,
            "values" : field.data.cgs.value
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
            
            request = pickle.loads(self.data)
            print("{} wrote:".format(self.client_address[0]))
            print(request)
            
            print("Getting simulation data")
            simid = request["simid"]
            Noutput = request["Noutput"]
            ddict = serialize_simdata_2d(simid, Noutput)
            payload = pickle.dumps(ddict)            

            # answer = request
            print(f"Sending simulation data for {simid} at {Noutput}")

            self.request.send(payload)
        except Exception as e:
            print(e)
            self.request.sendall(pickle.dumps(str(e)))

if __name__ == "__main__":
    HOST, PORT = "localhost", PORT

    # Create the server, binding to localhost on port 9999
    with socketserver.TCPServer((HOST, PORT), MyTCPHandler) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever(poll_interval=1)