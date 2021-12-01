import argparse
import sys

def main():
    options = parse_cli()

    options.func(options)

def run_server(options):
    from simdata_net.server import server
    server(options)

def run_client(options):
    from simdata_net.client import client
    client(options)


def parse_cli():
    
    
    parser = argparse.ArgumentParser()
    parser.set_defaults(func=lambda *args: parser.print_help(sys.stdout))

    subparsers = parser.add_subparsers()
    
    server_parser = subparsers.add_parser("server", help="Server mode.")
    client_parser = subparsers.add_parser("client", help="Client mode.")


    for p in [server_parser, client_parser]:
        p.add_argument("--port", type=int, default=-1, help="Server port")
        p.add_argument("--host", type=str, default="localhost", help="Host running the server.")
        p.add_argument("-v", action="store_true", help="Enable verbose output.")


    build_server_parser(server_parser)
    build_client_parser(client_parser)
    build_config_parser(subparsers)
    

    options = parser.parse_args()
    return options

def build_config_parser(subparsers):
    from simdata_net.config import build_parser
    config_parser = subparsers.add_parser("config", help="Handle config.")
    build_parser(config_parser)

def build_server_parser(parser):
    parser.add_argument("--start", action="store_true")
    parser.add_argument("--restart", action="store_true")
    parser.set_defaults(func=run_server)

def build_client_parser(parser):
    parser.add_argument("--url", type=str, help="Get the url.")
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
    parser.add_argument("-r", "--restart", action="store_true",
                        help="Restart the server.")
    parser.add_argument("--ping", action="store_true", help="Ping the server.")
    parser.set_defaults(func=run_client)
    



if __name__=="__main__":
    main()