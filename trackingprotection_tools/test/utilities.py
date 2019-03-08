from __future__ import absolute_import, print_function

import os
import threading
from os.path import dirname, realpath

from six.moves import socketserver
from six.moves.SimpleHTTPServer import SimpleHTTPRequestHandler

LOCAL_WEBSERVER_PORT = 8000
BASE_TEST_URL_DOMAIN = "localhost"
BASE_TEST_URL_NOPATH = "http://%s:%s" % (BASE_TEST_URL_DOMAIN,
                                         LOCAL_WEBSERVER_PORT)
BASE_TEST_URL = "%s/resources" % BASE_TEST_URL_NOPATH
BASE_TEST_URL_NOSCHEME = BASE_TEST_URL.split('//')[1]


class MyTCPServer(socketserver.TCPServer):
    """Subclass TCPServer to be able to reuse the same port (Errno 98)."""
    allow_reuse_address = True


def start_server():
    """ Start a simple HTTP server to run local tests."""
    print("Starting HTTP Server in a separate thread")
    # switch to test dir, this is where the test files are
    os.chdir(dirname(realpath(__file__)))
    server = MyTCPServer(
        ("localhost", LOCAL_WEBSERVER_PORT),
        SimpleHTTPRequestHandler
    )
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    print("...serving at port", LOCAL_WEBSERVER_PORT)
    return server, thread
