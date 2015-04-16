# Copyright (c) 2015 Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import socket

from BaseHTTPServer import HTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
from SocketServer import TCPServer

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer


class OVSFTPHandler(FTPHandler):
    authorizer = DummyAuthorizer()
    authorizer.add_anonymous("/tmp")


class TCPServerV6(HTTPServer):
    address_family = socket.AF_INET6


def main():
    SERVERS = {
        'ftp':   [FTPServer,   OVSFTPHandler,            21],
        'http':  [TCPServer,   SimpleHTTPRequestHandler, 80],
        'http6': [TCPServerV6, SimpleHTTPRequestHandler, 80],
    }

    parser = argparse.ArgumentParser(
            description='Run basic application servers.')
    parser.add_argument('proto', default='http', nargs='?',
            help='protocol to serve (http, http6, ftp)')
    args = parser.parse_args()

    if args.proto not in SERVERS:
        parser.print_help()
        exit(1)

    constructor = SERVERS[args.proto][0]
    handler = SERVERS[args.proto][1]
    port = SERVERS[args.proto][2]
    srv = constructor(('', port), handler)
    srv.serve_forever()


if __name__ == '__main__':
    main()