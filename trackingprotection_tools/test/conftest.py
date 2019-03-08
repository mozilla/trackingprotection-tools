from __future__ import absolute_import, print_function

import pytest

from . import utilities


@pytest.fixture(scope="session", autouse=True)
def prepare_test_setup(request):
    """Run an HTTP server during the tests."""
    print("\nStarting local_http_server")
    server, server_thread = utilities.start_server()

    def local_http_server_stop():
        print("\nClosing server thread...")
        server.shutdown()
        server_thread.join()

    request.addfinalizer(local_http_server_stop)
