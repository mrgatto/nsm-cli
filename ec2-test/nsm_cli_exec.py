#!/usr/local/bin/env python3

import argparse
import inspect
import subprocess as sp
import sys
import vsock
from os import path

current_dir = path.dirname(path.abspath(
    inspect.getfile(inspect.currentframe())))

NSM_CLI_BINARY = path.join(current_dir, 'nsm-cli')


def client_handler(args):
    client = vsock.VsockStream()
    endpoint = (args.cid, args.port)
    client.connect(endpoint)
    client.recv_data()


def server_handler(args):
    print("Starting server...")
    server = vsock.VsockListener()
    server.bind(args.port)

    proc = sp.Popen([NSM_CLI_BINARY, 'describe-pcr', '-i', '0'], stdout=sp.PIPE)
    #proc = sp.Popen([NSM_CLI_BINARY, 'describe-nsm'], stdout=sp.PIPE)
    #proc = sp.Popen([NSM_CLI_BINARY, 'get-random'], stdout=sp.PIPE)
    proc = sp.Popen([NSM_CLI_BINARY, 'attestation', '-d', 'custom_msg', '-r'], stdout=sp.PIPE)
    
    out, _ = proc.communicate()
    server.send_data(out)


def main():
    parser = argparse.ArgumentParser(prog='nsm-cli-exec')
    subparsers = parser.add_subparsers(title="options")

    client_parser = subparsers.add_parser("client", description="Client",
                                          help="Connect to a given cid and port.")
    client_parser.add_argument(
        "cid", type=int, help="The remote endpoint CID.")
    client_parser.add_argument(
        "port", type=int, help="The remote endpoint port.")
    client_parser.set_defaults(func=client_handler)

    server_parser = subparsers.add_parser("server", description="Server",
                                          help="Listen on a given port.")
    server_parser.add_argument(
        "port", type=int, help="The local port to listen on.")
    server_parser.set_defaults(func=server_handler)

    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit(1)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
