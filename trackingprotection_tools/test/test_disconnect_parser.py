from __future__ import absolute_import

import json
from os.path import join

import pytest

from ..DisconnectParser import DisconnectParser
from .basetest import BaseTest
from .utilities import BASE_TEST_URL

AD = {
    u"ad-trackerA-1.example",
    u"ad-trackerA-2.example",
    u"ad-trackerA-3.example",
    u"ad-trackerB.example",
    u"ad-trackerC-1.example",
    u"ad-trackerC-2.example"
}
REMAPPED_AD = {
    u"a.should-be-ad-tracker.example",
    u"b.should-be-ad-tracker.example",
    u"should-be-ad-tracker-small.example"
}
ANALYTICS = {
    u"analytics-trackerA-1.example",
    u"analytics-trackerA-2.example",
    u"analytics-trackerB.example"
}
REMAPPED_ANALYTICS = {
    u"should-be-analytics-tracker.example",
    u"also-should-be-analytics-tracker.example"
}
SOCIAL = {
    u"social-trackerA.example"
}
REMAPPED_SOCIAL = {
    u"should-be-social-tracker.example",
    u"should-be-social-tracker-small.example"
}
CONTENT = {
    u"content-trackerA.example",
    u"content-trackerB.example"
}
FINGERPRINTING = {
    u"fingerprinter.example",
    u"ad-trackerA.example",
    u"ad-trackerA-fingerprinting.example",
    u"example.com"
}
CRYPTOMINING = {
    u"example.com"
}
SESSION_REPLAY = {
   u"ad-trackerA-1.example",
   u"ad-trackerA-2.example",
   u"ad-trackerA-3.example",
   u"analytics-trackerB.example"
}
PERFORMANCE = {
    u"ad-trackerA-1.example",
    u"ad-trackerA-2.example",
    u"ad-trackerA-3.example",
    u"ad-trackerB.example",
    u"a.should-be-ad-tracker.example",
    u"b.should-be-ad-tracker.example",
    u"should-be-analytics-tracker.example",
    u"should-be-social-tracker.example"
}
DNT_W3C = {
    u"ad-trackerB.example",
    u"analytics-trackerA-1.example",
    u"analytics-trackerA-2.example",
    u"should-be-ad-tracker-small.example",
    u"should-be-social-tracker-small.example"
}
DNT_EFF = {
    u"ad-trackerA-1.example",
    u"ad-trackerA-2.example",
    u"ad-trackerA-3.example"
}
ALL_CATEGORIES = [
    'Advertising', 'Analytics', 'Fingerprinting', 'Cryptomining',
    'Social', 'Content'
]
ALL_TEST_DOMAINS = AD.union(REMAPPED_AD).union(
    ANALYTICS).union(REMAPPED_ANALYTICS).union(
    SOCIAL).union(REMAPPED_SOCIAL).union(
    CONTENT).union(CRYPTOMINING).union(FINGERPRINTING)


class TestDisconnectParser(BaseTest):

    @pytest.fixture(autouse=True)
    def create_parsers(self):
        self.blocklist_file = join(self.RESOURCE_DIR, 'test-blocklist.json')
        with open(self.blocklist_file, 'r') as f:
            self.blocklist = json.load(f)
        self.entitylist_file = join(self.RESOURCE_DIR, 'test-entitylist.json')
        with open(self.entitylist_file, 'r') as f:
            self.entitylist = json.load(f)
        self.mapping_file = join(self.RESOURCE_DIR, 'test-mapping.json')
        with open(self.mapping_file, 'r') as f:
            self.mapping = json.load(f)

        self.parser = DisconnectParser(
            self.blocklist_file,
            self.entitylist_file,
            disconnect_mapping=self.mapping_file
        )
        self.parser_no_remap = DisconnectParser(
            self.blocklist_file
        )

    def test_list_parsing(self):
        remote = DisconnectParser(
            blocklist_url=BASE_TEST_URL + '/test-blocklist.json',
            entitylist_url=BASE_TEST_URL + '/test-entitylist.json',
            disconnect_mapping_url=BASE_TEST_URL + '/test-mapping.json'
        )
        assert remote._blocklist == self.parser._blocklist
        assert len(remote._entitylist) > 0
        for url, resources in remote._entitylist.items():
            assert resources == self.parser._entitylist[url]
        assert (remote.get_domains_with_category(ALL_CATEGORIES)
                == self.parser.get_domains_with_category(ALL_CATEGORIES))
        assert (set(remote._disconnect_mapping.items())
                == set(self.parser._disconnect_mapping.items()))

        with pytest.raises(ValueError):
            DisconnectParser(
                blocklist=join(self.RESOURCE_DIR, 'test-blocklist.json'),
                blocklist_url=BASE_TEST_URL+'/test-blocklist.json'
            )
        with pytest.raises(ValueError):
            DisconnectParser()

        with pytest.raises(RuntimeError):
            DisconnectParser(
                blocklist_url=BASE_TEST_URL+'/test-blocklist-doesnt-exist.json'
            )

    def test_category_retrieval(self):
        assert self.parser.get_domains_with_category(
            'Advertising') == AD.union(REMAPPED_AD)
        assert self.parser_no_remap.get_domains_with_category(
            'Advertising') == AD
        assert self.parser.get_domains_with_category(
            'Analytics') == ANALYTICS.union(REMAPPED_ANALYTICS)
        assert self.parser_no_remap.get_domains_with_category(
            'Analytics') == ANALYTICS
        assert self.parser.get_domains_with_category(
            'Social') == SOCIAL.union(REMAPPED_SOCIAL)
        assert self.parser_no_remap.get_domains_with_category(
            'Social') == SOCIAL
        assert self.parser.get_domains_with_category(
            'Content') == CONTENT
        assert self.parser_no_remap.get_domains_with_category(
            'Content') == CONTENT
        assert self.parser.get_domains_with_category(
            'Cryptomining') == CRYPTOMINING
        assert self.parser_no_remap.get_domains_with_category(
            'Cryptomining') == CRYPTOMINING
        assert self.parser.get_domains_with_category(
            'Fingerprinting') == FINGERPRINTING
        assert self.parser_no_remap.get_domains_with_category(
            'Fingerprinting') == FINGERPRINTING
        # Bogus category
        with pytest.raises(KeyError):
            self.parser.get_domains_with_category('Bogus')

    def test_multiple_categories(self):
        assert self.parser.get_domains_with_category(
            ['Advertising']) == AD.union(REMAPPED_AD)
        assert (
            self.parser.get_domains_with_category(['Advertising', 'Analytics'])
            == AD.union(REMAPPED_AD).union(ANALYTICS).union(REMAPPED_ANALYTICS)
        )
        assert (
            self.parser.get_domains_with_category(
                ['Fingerprinting', 'Cryptomining'])
            == FINGERPRINTING.union(CRYPTOMINING)
        )

        assert (self.parser.get_domains_with_category(ALL_CATEGORIES) ==
                ALL_TEST_DOMAINS)

        # Bogus category
        with pytest.raises(KeyError):
            self.parser.get_domains_with_category(['Foo', 'Bar'])

    def test_tag_retrieval(self):
        # single tag
        assert self.parser.get_domains_with_tag(
            'session-replay') == SESSION_REPLAY
        assert self.parser_no_remap.get_domains_with_tag(
            'session-replay') == SESSION_REPLAY
        assert self.parser.get_domains_with_tag(
            'performance') == PERFORMANCE
        assert self.parser_no_remap.get_domains_with_tag(
            'performance') == PERFORMANCE

        # multi-tag
        assert self.parser.get_domains_with_tag(
            ['session-replay']) == SESSION_REPLAY
        assert self.parser_no_remap.get_domains_with_tag(
            ['session-replay']) == SESSION_REPLAY
        assert (
            self.parser.get_domains_with_tag(['session-replay', 'performance'])
            == SESSION_REPLAY.union(PERFORMANCE)
        )
        assert (
            self.parser_no_remap.get_domains_with_tag(
                ['session-replay', 'performance']
            ) == SESSION_REPLAY.union(PERFORMANCE)
        )

        # dnt
        assert self.parser.get_domains_with_tag(
            'eff') == DNT_EFF
        assert self.parser_no_remap.get_domains_with_tag(
            'eff') == DNT_EFF
        assert self.parser_no_remap.get_domains_with_tag(
            'w3c') == DNT_W3C
        assert self.parser.get_domains_with_tag(
            'w3c') == DNT_W3C
        assert self.parser.get_domains_with_tag(
            ['eff', 'w3c']) == DNT_EFF.union(DNT_W3C)
        assert self.parser_no_remap.get_domains_with_tag(
            ['eff', 'w3c']) == DNT_EFF.union(DNT_W3C)
        assert (
            self.parser_no_remap.get_domains_with_tag(
                ['session-replay', 'w3c']
            ) == SESSION_REPLAY.union(DNT_W3C)
        )
        assert (
            self.parser.get_domains_with_tag(['session-replay', 'w3c'])
            == SESSION_REPLAY.union(DNT_W3C)
        )
        assert (
            self.parser_no_remap.get_domains_with_tag(
                ['session-replay', 'w3c']
            ) == SESSION_REPLAY.union(DNT_W3C)
        )

        # Ensure we don't throw an error with an unknown tag
        assert len(self.parser.get_domains_with_tag('bogus')) == 0
