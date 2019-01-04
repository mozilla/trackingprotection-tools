#!/usr/bin/python3

import re
from collections import defaultdict
import domain_utils as du
import json

with open('easylist.txt', 'r') as f:
    easyList = f.read().strip().split('\n')
with open('easyprivacy.txt', 'r') as f:
    easyPrivacy = f.read().strip().split('\n')
with open('fanboy-annoyance.txt', 'r') as f:
    fanBoyAnnoyance = f.read().strip().split('\n')
with open('fanboy-social.txt', 'r') as f:
    fanBoySocial = f.read().strip().split('\n')
with open('adservers.txt', 'r') as f:
    adGuard = f.read().strip().split('\n')

# Rules with these options apply only to requests that originate from one of these types
TYPE_OPTIONS = ['script', 'image', 'stylesheet',
                'object', 'object-subrequest', 'subdocument',
                'xmlhttprequest', 'websocket', 'media', 'font',
                'ping', 'other']

# Rules with these options aren't relevant to the project
RULES_TO_SKIP = ['document', 'elemhide', 'generichide', 'genericblock',
                 'popup', 'csp']


class ABPRule:
    """A simple rule parsing class for individual rules.
    
    For defintions see: https://adblockplus.org/filter-cheatsheet
    plus: https://adblockplus.org/en/filters
    plus: https://github.com/gorhill/uBlock/wiki/Static-filter-syntax
    """

    def __init__(self, rule):
        self._rule = rule
        self._parse_options()

    def _parse_options(self):
        """Parse options off of rule.
        multi-part options (domain and rewrite) are saved directly
        boolean options are mapped to True/False as follows:
            image  --> self._options['image'] returns True
            ~image --> self._options['image'] returns False
        """
        if '$' not in self._rule:
            self._options = dict()
            return
        raw_options = self._rule.split('$')[1]
        parts = [x.split('=') for x in raw_options.split(',')]
        self._options = dict([tuple(x) if len(x) == 2 else (
            x[0] if not x[0].startswith('~') else x[0][1:], not x[0].startswith('~')
        ) for x in parts])

        # Remove ublock origin specific 'first-party' option by converting to 'third-party'
        val = self._options.pop('first-party', None)
        if val is not None:
            self._options['third-party'] = not val

    def get_domain(self):
        part = self._rule
        if '||' in part:
            part = self._rule.split('||')[1]
        return re.split('[\\^$/?]', part)[0]

    def get_ps1(self):
        return du.get_ps_plus_1('http://' + self.get_domain())

    def has_path(self):
        """Simple heuristic to determine if rule has a non-empty path"""
        part = self._rule.split('$')[0]  # domain + path always before $
        return (
                ('/' in part and not ('^' not in part and part.count('/') == 1 and part.endswith('/')))
                or ('^' in part and part[-1] != '^')
        )

    def get_path(self):
        if not self.has_path():
            return
        part = self._rule.split('$')[0]  # domain + path always before $
        part = part.split('?')[0]  # exclude query params

        if '^' in part and '/' in part:
            if part.index('^') < part.index('/'):
                return part.split('^', 1)[1]
            else:
                return part.split('/', 1)[1].split('^', 1)[0]
        elif '^' in part:
            return part.split('^', 1)[1]
        elif '/' in part:
            return part.split('/', 1)[1]
        else:
            print("Unexpected path format: %s" % self._rule)
        return

    def get_domain_option(self, drop_negations=False):
        if 'domain' not in self._options:
            return
        domains = self._options['domain'].split('|')
        if drop_negations:
            domains = [x for x in domains if not x.startswith('~')]
        return domains

    def has_option(self, option):
        return option in self._options

    def has_options(self, options):
        return [self.has_option(x) for x in options]

    def get_option(self, option):
        return self._options.get(option, None)


def get_domain_rules(rules):
    """Filter ABP list to domains (||) without options"""
    return [ABPRule(x) for x in rules if x.startswith('||')]


def get_exception_rules(rules):
    """Filter ABP list to exceptions"""
    return [ABPRule(x) for x in rules if x.startswith('@@||')]


def get_abp_domain_rules(rules, skip_paths=False, skip_types=True):
    # map first-party domain to third-party domain
    domains = defaultdict(set)

    for rule, rule_type in rules:
        if any(rule.has_options(RULES_TO_SKIP)):
            continue

        domain = rule.get_domain().lower().split(':')[0]  # ensure domains are all lowercase, drop ports

        # Filter out wildcard domains, we don't support them
        if '*' in domain:
            if '*.' in domain and '.' in domain.split('*.')[1]:
                domain = domain.split('*.')[1]
            else:
                continue

        # Skip rules with paths
        if skip_paths and rule.has_path():
            continue

        # Skip rules with types
        if skip_types and any(rule.has_options(TYPE_OPTIONS)):
            continue

        # Add path if it exists and does not contain a wildcard
        path = rule.get_path()
        if path is not None and '*' not in path and path != '|':
            tp = domain + '/' + path
        else:
            tp = domain

        fps = rule.get_domain_option(drop_negations=True)
        if fps is None:
            domains[domain].add(tp)

    return domains


def get_abp_exception_rules(rules, skip_paths=False, skip_types=True):
    # map first-party domain to third-party domain
    exception_rules = defaultdict(set)

    for rule, rule_type in rules:
        if any(rule.has_options(RULES_TO_SKIP)):
            continue

        tp = rule.get_domain().lower().split(':')[0]  # ensure domains are all lowercase, drop ports

        # Filter out wildcard domains, we don't support them
        if '*' in tp:
            if '*.' in tp and '.' in tp.split('*.')[1]:
                tp = tp.split('*.')[1]
            else:
                continue

        # Skip rules with paths
        if skip_paths and rule.has_path():
            continue

        # Skip rules with types
        if skip_types and any(rule.has_options(TYPE_OPTIONS)):
            continue

        exception_rules[tp].add(tp)

    return exception_rules


def write_domain_rules_to_json(rules, list_name, file):
    current_license = 'https://easylist.to/pages/licence.html'
    # currentLicense = [i for i, x in enumerate(easyList) if x.startswith('! License')]
    rules_dict = {'license': current_license, 'categories': {list_name: []}}
    abp_domain_rules = get_abp_domain_rules([(x, 'domain') for x in get_domain_rules(rules)])
    for url in abp_domain_rules:
        url_dict = {url: {url: list(abp_domain_rules[url])}}
        rules_dict['categories'][list_name].append(url_dict)
    json.dump(rules_dict, file, indent=1)


def write_entitylist_rules_to_json(rules, file):
    rules_dict = {}
    abp_exception_rules = get_abp_exception_rules([(x, 'exception') for x in get_domain_rules(rules)])
    for url in abp_exception_rules:
        url_dict = {url: {"properties": list(abp_exception_rules[url]),
                          "resources": list(abp_exception_rules[url])}}
        rules_dict.update(url_dict)
    json.dump(rules_dict, file, indent=1)


def writeLists(listName, listContents):
    with open(listName + "-blacklist.json", 'w') as f:
        write_domain_rules_to_json(listContents, listName, f)
    with open(listName + "-entitylist.json", 'w') as f:
        write_entitylist_rules_to_json(listContents, f)


for (listName, listContents) in (('EasyList', easyList), ('EasyPrivacy', easyPrivacy),
                                 ('fanBoyAnnoyance', fanBoyAnnoyance), ('fanBoySocial', fanBoySocial),
                                 ('adGuard', adGuard)):
    writeLists(listName, listContents)
