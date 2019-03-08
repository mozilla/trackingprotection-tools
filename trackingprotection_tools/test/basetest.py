from __future__ import absolute_import

import os
from os.path import dirname, isfile, join, realpath

import pytest


class BaseTest(object):
    RESOURCE_DIR = join(dirname(realpath(__file__)), 'resources')

    @pytest.fixture(autouse=True)
    def set_tmpdir(self, tmpdir):
        """Create a tmpdir fixture to be used in `get_test_config`.

        Based on:
        https://mail.python.org/pipermail/pytest-dev/2014-April/002484.html
        """
        self.tmpdir = str(tmpdir)

    def is_installed(self, cmd):
        """Check if a program is available via the standard PATH lookup."""
        path = os.environ["PATH"].split(os.pathsep)
        for d in path:
            candidate = join(d, cmd)
            if isfile(candidate) and os.access(candidate, os.X_OK):
                return True
        return False

    def assert_is_installed(self, cmd):
        assert self.is_installed(cmd), 'Cannot find %s in your system' % cmd

    def assert_py_pkg_installed(self, pkg):
        # some modules are imported using a different name than the ones used
        # at the installation.
        pkg_name_mapping = {
            "pyopenssl": "OpenSSL",
            "beautifulsoup4": "bs4",
            "python-dateutil": "dateutil",
            "flake8-isort": "flake8_isort",
            "mini-amf": "miniamf",
            "pillow": "PIL"
        }
        # get the mapped name if it exists.
        pkg_importable = pkg_name_mapping.get(pkg.lower(), pkg)
        try:
            __import__(pkg_importable)
        except ImportError:
            pytest.fail("Cannot find python package %s in your system" % pkg)
