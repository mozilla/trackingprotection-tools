import json
import os

from openwpm_utils import domain as du
from six.moves.urllib.parse import urlparse

DNT_TAG = 'dnt'
FINGERPRINTING_TAG = 'fingerprinting'
CRYPTOMINING_TAG = 'cryptominer'
SESSION_REPLAY_TAG = 'session-replay'
PERFORMANCE_TAG = 'performance'
DISCONNECT_TAGS = {
    FINGERPRINTING_TAG, CRYPTOMINING_TAG, SESSION_REPLAY_TAG, PERFORMANCE_TAG
}


class DisconnectParser(object):
    """A parser for the Disconnect list.

    This partser is meant to use the list as it is used in Firefox's URL
    classifier. This does not necessarily match the implementation of
    Disconnect's own extension or any other consumer of the Disconnect list"""
    def __init__(self, blocklist, entitylist, categories_to_exclude=[],
                 disconnect_mapping=None, verbose=False):
        """Initialize the parser.

        Parameters
        ----------
        blocklist : string
            The file location of the blocklist. The canonical blocklist from
            Disconnect repo is likely most up to date. See:
            https://github.com/disconnectme/disconnect-tracking-protection/
        whitelist : string
            The file location of the entitylist. This is a Firefox-specific
            list. See: https://github.com/mozilla-services/shavar-prod-lists/
        categories_to_exclude : list
            A list of list categories to exclude. Firefox currently excludes
            the `Content` category by default. (default empty list)
        disconnect_mapping : string
            A file location of the disconnect category remapping file in json
            format. The canonical source of remapping info is:
            https://github.com/mozilla-services/shavar-list-creation/blob/master/disconnect_mapping.py
        verbose : boolean
            Set to True to print list parsing info.
        """
        self.verbose = verbose
        self._exclude = set([x.lower() for x in categories_to_exclude])
        self._should_remap = disconnect_mapping is not None
        if self._should_remap:
            with open(os.path.expanduser(disconnect_mapping), 'r') as f:
                self.disconnect_mapping = json.load(f)
        self._raw_blocklist = self._load_list(blocklist)
        rv = self._parse_blocklist(self._raw_blocklist)
        self._categorized_blocklist, self._tagged_domains = rv
        self._blocklist = self._flatten_blocklist(self._categorized_blocklist)
        self._raw_entitylist = self._load_list(entitylist)
        self._entitylist = self._parse_entitylist(self._raw_entitylist)

    def _load_list(self, location):
        """Load the list from disk and return a json object"""
        with open(location, 'r') as f:
            json_list = json.load(f)
        return json_list

    def _remap_disconnect(self, blocklist):
        """Remap the "Disconnect" category

        This contains a bunch of hardcoded logic for remapping the Disconnect
        category as specified here:
            https://github.com/mozilla-services/shavar-prod-lists#blacklist

        Returns
        -------
        dict : Maps categories to sets of domains.
        """
        remapped = {
            'Social': set(),
            'Analytics': set(),
            'Advertising': set()
        }
        for domain, category in self.disconnect_mapping.items():
            if len(domain) == 1:
                raise ValueError(
                    "Unexpected domain of length 1 in category %s "
                    "This likely means the list parser needs to be updated." %
                    (category))
            remapped[category].add(domain)
        return remapped

    def _is_domain_key(self, key):
        """Return `True` if the key appears to be a domain key

        Unfortunately the list does not currently provide a structured way to
        differentiate between sub-category tags (like `fingerprinting`) from
        the lists of resources that belong to an organization. We use the
        heuristic of whether the key starts with http or ends in a slash to
        mark resource lists.
        """
        return key.startswith('http') or key.endswith('/')

    def _parse_blocklist(self, blocklist):
        """Parse raw blocklist into a format that's easier to work with"""
        if self.verbose:
            print("Parsing raw list into categorized list...")
        count = 0
        collapsed = dict()
        tagged_domains = dict()
        if self._should_remap:
            remapping = self._remap_disconnect(blocklist)
        for cat in blocklist['categories'].keys():
            count = 0
            collapsed[cat] = set()
            if self._should_remap and cat in remapping:
                collapsed[cat] = collapsed[cat].union(remapping[cat])
                if self.verbose:
                    print("Remapping %d domains from Disconnect to %s" % (
                        len(remapping[cat]), cat))
                count += len(remapping[cat])
            for item in blocklist['categories'][cat]:
                for org, urls in item.items():
                    # Parse out sub-category. The way the list is structured,
                    # we must first iterate through all items to gather
                    # the categories and then iterate again to apply these
                    # categories to domains. Categories are assumed to apply to
                    # all resources in an organization.
                    tags = set()
                    for k, v in urls.items():
                        if self._is_domain_key(k):
                            continue
                        if k in DISCONNECT_TAGS:
                            if v == "true":
                                tags.add(k)
                            continue
                        elif k == DNT_TAG:
                            tags.add(v)
                            continue
                        raise ValueError(
                            "Unsupported record type %s in organization %s. "
                            "This likely means the list changed and the "
                            "parser should be updated." % (k, org))
                    for url, domains in urls.items():
                        if not self._is_domain_key(url):
                            continue
                        for domain in domains:
                            if len(domain) == 1:
                                raise ValueError(
                                    "Unexpected domain of length 1 in "
                                    "resource list %s under organization %s. "
                                    "This likely means the parser needs to be "
                                    "updated due to a list format change." %
                                    (domains, org))
                            for tag in tags:
                                if tag not in tagged_domains:
                                    tagged_domains[tag] = set()
                                tagged_domains[tag].add(domain)
                            if self._should_remap and cat == 'Disconnect':
                                continue
                            collapsed[cat].add(domain)
                            count += 1

        return collapsed, tagged_domains

    def _flatten_blocklist(self, blocklist):
        """Generate a flattened version of the blocklist category map"""
        if self.verbose:
            print("Parsing categorized list into single blocklist...")
        out = set()
        for category, domains in self._categorized_blocklist.items():
            if category.lower() in self._exclude:
                if self.verbose:
                    print("Skipping %s" % category)
                continue
            if self._should_remap and category == 'Disconnect':
                if self.verbose:
                    print("Skipping Disconnect as it is remapped")
                continue
            if self.verbose:
                print("Added %i domains for category %s" % (
                    len(domains), category))
            out = out.union(domains)
        return out

    def _parse_entitylist(self, entitylist):
        """Parse raw entitylist into a format that's easier to work with"""
        out = dict()
        for org in entitylist.keys():
            for url in entitylist[org]['properties']:
                out[url] = entitylist[org]['resources']
        return out

    def should_whitelist(self, url, top_url):
        """Check if `url` is whitelisted on `top_url` due to the entitylist

        Parameters
        ----------
        url : string
            The URL or hostname to classify.
        top_url : string
            The URL or hostname of the top-level page on which `url` was loaded

        Returns
        -------
        boolean : True if the url would have been whitelisted by the entitylist
        """
        if not url.startswith('http'):
            url = 'http://' + url
        if not top_url.startswith('http'):
            top_url = 'http://' + top_url
        top_host = urlparse(top_url).hostname
        top_ps1 = du.get_ps_plus_1(top_url)
        url_host = urlparse(url).hostname
        url_ps1 = du.get_ps_plus_1(url)
        if top_host in self._entitylist:
            resources = self._entitylist[top_host]
        elif top_ps1 in self._entitylist:
            resources = self._entitylist[top_ps1]
        else:
            return False
        return url_host in resources or url_ps1 in resources

    def should_block_with_match(self, url, top_url=None):
        """Check if Firefox's Tracking Protection would block this request.

        The return value includes the matching rule and whether or not the
        `url` was explicitly blacklisted, whitelisted, or just not found.

        Firefox blocks domains from the Disconnect list following the
        Safebrowsing parsing rules detailed here:
        https://developers.google.com/safe-browsing/v4/urls-hashing#suffixprefix-expressions

        Parameters
        ----------
        url : string
            The URL or hostname to classify.
        top_url : string
            (optional) The URL or hostname of the top-level page on which `url`
            was loaded. If this is not provided, the entitylist is not checked.

        Returns
        -------
        string : `blacklisted`, `whitelisted`, or None
        string : The matching domain (only supported for blocking) or None
        """
        if not url.startswith('http'):
            url = 'http://' + url

        if top_url is not None and self.should_whitelist(url, top_url):
            return 'whitelisted', None

        # Check exact hostname
        hostname = urlparse(url).hostname
        if hostname in self._blocklist:
            return 'blacklisted', hostname

        # Skip IP address
        if du.is_ip_address(hostname):
            return None, None

        # Check up to four hostnames formed by starting with the last five
        # components and successively removing the leading component
        # NOTE: The top-level domain should be skipped, but this is currently
        # not implemented in Firefox. See: Bug 1203635.
        hostname = '.'.join(hostname.rsplit('.', 5)[1:])
        # ps1 = ps1 = du.get_ps_plus_1(url)  # blocked on Bug 1203635
        count = 0
        while hostname != '':
            count += 1
            if count > 4:
                return None, None
            if hostname in self._blocklist:
                return 'blacklisted', hostname
            # Skip top-level domain (blocked on Bug 1203635)
            # if hostname == ps1:
            #     return None, None
            try:
                hostname = hostname.split('.', 1)[1]
            except IndexError:
                return None, None
        return None, None

    def should_block(self, url, top_url=None):
        """Check if Firefox's Tracking Protection would block this request

        Parameters
        ----------
        url : string
            The URL or hostname to classify.
        top_url : string
            (optional) The URL or hostname of the top-level page on which `url`
            was loaded. If this is not provided, the entitylist is not checked.

        Returns
        -------
        boolean : True if the url would have been blocked by Disconnect.
        """
        result, match = self.should_block_with_match(url, top_url)
        return result == 'blacklisted'

    def contains_domain(self, hostname):
        """Returns True if the Disconnect list contains that exact hostname"""
        return hostname in self._blocklist

    def contains_ps1(self, hostname):
        """Returns True if the Disconnect list contains any domains from ps1"""
        if not hostname.startswith('http'):
            hostname = 'http://' + hostname
        return du.get_ps_plus_1(hostname) in self._blocklist

    def get_matching_domains(self, hostname):
        """Returns all domains that match or are subdomains of hostname"""
        return [x for x in self._blocklist if x.endswith(hostname)]

    def get_domains_with_category(self, categories):
        """Returns all domains with the top-level categories

        Parameters
        ----------
        categories : string or list of strings
            One or more top-level categories to pull from the list

        Returns
        -------
        set : All domains / rules under `categories`.
        """
        if not type(categories) == list:
            categories = [categories]
        out = set()
        for category in categories:
            out.update(self._categorized_blocklist[category])
        return out

    def get_domains_with_tag(self, tags):
        """Returns all domains with the top-level categories

        Parameters
        ----------
        tags : string or list of strings
            One or more top-level sub-category tags to pull from the list.
            To specify `dnt` tags, use the type: `eff` or `w3c`.

        Returns
        -------
        set : All domains / rules under `categories`.
        """
        if not type(tags) == list:
            tags = [tags]
        out = set()
        for tag in tags:
            out.update(self._tagged_domains[tag])
        return out
