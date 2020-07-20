from ..DisconnectReporting import DisconnectReport

import json
import os
from os.path import dirname, realpath

REPORTS_PATH = "./resources/reports/"


def test_empty_report():
    report = DisconnectReport()
    report_json = json.loads(report._report_to_json())
    assert report_json == json.loads('{"domains": {}}')


def test_add_domain():
    report = DisconnectReport()
    report.add_domain("http://example.com",
                      "Testing", "tracker", "It just seems suspicious")
    report_dict = json.loads(report._report_to_json())
    os.chdir(dirname(realpath(__file__)))
    with open(os.path.join(REPORTS_PATH, "add_domain.json"), 'r') as f:
        assert report_dict == json.load(f)


def test_add_comment():
    report = DisconnectReport()
    report.add_domain("http://example.com",
                      "Testing", "tracker", "It just seems suspicious")
    report.add_comment("http://example.com",
                       "This is my comment on example.com")
    report_dict = json.loads(report._report_to_json())
    os.chdir(dirname(realpath(__file__)))
    with open(os.path.join(REPORTS_PATH, "add_comment.json"), 'r') as f:
        assert report_dict == json.load(f)


def test_add_observation():
    report = DisconnectReport()
    report.add_domain("http://example.com",
                      "Testing", "tracker", "It just seems suspicious")
    report.add_observation("http://example.com", "http://domain.invalid",
                           "http://example.com/a_bad_script.js",
                           metadata={"meta": "data"})
    report_dict = json.loads(report._report_to_json())
    os.chdir(dirname(realpath(__file__)))
    with open(os.path.join(REPORTS_PATH, "add_observation.json"), 'r') as f:
        assert report_dict == json.load(f)
