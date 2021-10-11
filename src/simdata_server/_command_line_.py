import argparse

def main():
    options = parse_cli()

    if options.function == "server":
        from simdata_server.server import server as func
    else:
        from simdata_server.client import client as func

    func(options)

def parse_cli():
    
    
    parser = argparse.ArgumentParser()
    
    parser.add_argument("--port", type=int, help="Server port")
    parser.add_argument("--host", type=str, help="Host running the server.")
    parser.add_argument("-v", action="store_true", help="Enable verbose output.")

    subparsers = parser.add_subparsers()
    
    server_parser = subparsers.add_parser("server", help="Server mode.")
    client_parser = subparsers.add_parser("client", help="Client mode.")
    
    server_parser.add_argument("--host", type=str, default="localhost",
                        help="Server address")
    server_parser.add_argument("--port", type=int, default=-1,
                        help="Server port")
    server_parser.add_argument("--start", action="store_true")
    server_parser.add_argument("--restart", action="store_true")



    client_parser.add_argument("--simid", type=str,
                        help="The id identifying the simulation.")
    client_parser.add_argument("--var", type=str,
                        help="Variable to get.")
    client_parser.add_argument("--N", type=int,
                        help="Output number.")
    client_parser.add_argument("--dim", type=int,
                        help="Data dimension.")
    client_parser.add_argument("--planet", type=int,
                        help="Number of planet.")
    client_parser.add_argument("-o", "--outfile",
                        help="Output file to store the data in.")
    client_parser.add_argument("-k", "--kill", action="store_true",
                        help="Kill the server.")
    client_parser.add_argument("--ping", action="store_true", help="Ping the server.")
    
    options = parser.parse_args()
    return options



if __name__=="__main__":
    main()