import json
import os
import zipfile
from datetime import datetime

import requests
import six

CLASSIFICATIONS = {
    'tracker',   # to be used when futher categorization is unknown
    'analytics', 'advertising', 'social', 'content',
    'cryptominer', 'fingerprinting', 'session-replay'
}


class DisconnectReport(object):
    """A class to build json-formatted tracker reports from measurement data

    This helper class should be used to summarize the results measurement data
    in a standard format that can be shared with Disconnect.
    """
    def __init__(self):
        self._domains = dict()
        self._content = dict()  # maps domain to (content_hash, content)
        return

    def generate_report(self, root_dir, compressed=False):
        """Generate a final output report for Disconnect

        Parameters
        ----------
        root_dir : string
            Root directory in which to save the generated report
        compressed : boolean
            Set to True to compress the final output report
        """
        root_dir = os.path.expanduser(root_dir)
        if not os.path.isdir(root_dir):
            os.makedirs(root_dir)
        fname = datetime.strftime(
            datetime.utcnow(),
            '%Y-%m-%d-domain_report.json'
        )
        print("Writing report to: %s" % os.path.join(root_dir, fname))

        output = dict()
        output['domains'] = self._domains
        if len(self._content) > 0:
            output['scripts'] = self._get_content()

        if compressed:
            raise NotImplementedError(
                "Compression is not yet supported"
            )
        else:
            with open(os.path.join(root_dir, fname), 'w') as f:
                json.dump(output, f)

    def _get_content(self):
        """Get script content for output report"""
        out = dict()
        for domain, script in self._content.items():
            for content_hash, content in script:
                out[content_hash] = content
        return out

    def _get_report(self, domain):
        """Get data entered for `domain`"""
        if domain not in self._domains:
            raise ValueError(
                "Domain %s has not yet been added to the report. Add this "
                "domain with `add_domain`" % domain)
        return self._domains[domain]

    def add_domains(self, domains, source, classification, reason):
        """Add a set of `domains` to the report with the given metadata.

        Parameters
        ----------
        domain : list of strings or set of strings or tuple of strings
            Domains for which to generate a report.
        source : string
            Dataset / crawl the domain was flagged in (if any)
        classification : string
            Category for which this domain was flagged.
            Note: must be one of the values given in CLASSIFICATIONS
        reason : string
            A description of the detection methodology
        """
        if type(domains) == list:
            domains = set(domains)
        elif type(domains) == tuple:
            domains = domains
        elif type(domains) != set:
            raise ValueError(
                "Domain should be a string, list of strings, or a set of "
                "strings"
            )

        if len(domains.intersection(self._domains)) > 0:
            raise ValueError("Domains %s are already in the report" %
                             domains.intersection(self._domains))
        for domain in domains:
            self.add_domain(domain, source, classification, reason)

    def add_domain(self, domain, source, classification, reason):
        """Add a `domain` to the report with a given `classification`.

        Parameters
        ----------
        domain : string
            Domain for which to generate a report.
        source : string
            Dataset / crawl the domain was flagged in (if any)
        classification : string
            Category for which this domain was flagged.
            Note: must be one of the values given in CLASSIFICATIONS
        reason : string
            A description of the detection methodology
        """
        if classification.lower() not in CLASSIFICATIONS:
            raise ValueError(
                "Classification must be one of the supported types.\n"
                "You provided classification %s. The supported types are:\n"
                "%s." % (classification, CLASSIFICATIONS))
        if domain in self._domains:
            raise ValueError("Domain %s already in report" % domain)
        self._domains[domain] = dict()
        report = self._get_report(domain)
        report['classification'] = classification
        report['source'] = source
        report['reason'] = reason

    def add_observation(self, domain, site_url, resource_url,
                        content_hash=None, content=None):
        """Add observations of `domain` to the report.

        Observations give context to where the domain was found.

        Parameters
        ----------
        domain : string
            Domain for which to generate a report
        site_url : string
            Top-level URL on which this resource was loaded
        resource_url : string
            The resource loaded from `domain`
        content_hash : string (optional)
            Hash of the content of the resource
        content : string (optional)
            Response body content for the instance of `resource_url`
        """
        report = self._get_report(domain)
        if 'observations' not in report:
            report['observations'] = list()
        if content_hash is not None and content is not None:
            if domain not in self._content:
                self._content[domain] = list()
            self._content[domain].append((content_hash, content))
            report['observations'].append(
                (site_url, resource_url, content_hash))
        else:
            report['observations'].append((site_url, resource_url))

    def add_comment(self, domain, comment, drop_duplicates=True):
        """Add freeform `comment` to report under `domain`

        New comments append to existing comments (with a line break added).

        Parameters
        ----------
        domain : string or list of strings
            Domain(s) for which to add comments.
            Set domain to `*` to add comments for all domains in report.
        comment : string
            Comment to add for domain
        drop_duplicates : boolean (default True)
            Set to True to drop duplicate comments
        """
        if not isinstance(domain, six.string_types):
            domain = [domain]
        for item in domain:
            report = self._get_report(item)
            if 'comments' not in report:
                report['comments'] = list()
            if drop_duplicates and comment in report['comments']:
                continue
            report['comments'].append(comment)


def send_report_to_disconnect(username, password, endpoint, reports):
    """Submit reports created by `DisconnectReport` to Disconnect.

    Parameters
    ----------
    username : string
        Username used to access the reporting service
    password : string
        Password used to access the reporting service
    endpoint : string
        URL of the reporting service endpoint
    reports : list of strings
        List of file locations of json-formatted reports produced
        by `DisconnectReport::generate_report`
    """

    # Prepare zip archive in memory
    archive_buffer = six.BytesIO()
    archive = zipfile.ZipFile(archive_buffer, 'a')
    for report in reports:
        if not os.path.isfile(report):
            raise ValueError(
                "The specified report `%s` is not found or is not a "
                "file." % report
            )
        print("Adding report %s to submission archive..." % report)
        with open(report, 'rb') as f:
            content = f.read()
        archive.writestr(os.path.basename(report), content)
    archive.close()

    # Send report
    files = {'payload': archive_buffer.getvalue()}
    print("Sending POST request with reports to endpoint %s..." % endpoint)
    r = requests.post(endpoint, files=files, auth=(username, password))
    print("HTTP Response code: %s" % r)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="Send reports to Disconnect")
    parser.add_argument(
        'reports',
        metavar='/path/to/report.json',
        type=six.text_type,
        nargs='+',
        help='full path to report files generated by DisconnectReport'
    )
    parser.add_argument(
        '--credentials',
        dest='credential_file',
        default='./credentials',
        help=("full path to credential that contains the endpoint, username, "
              "and password for the Disconnect reporting service (in that "
              "order, each separated by a line break). "
              "(Default: `./credentials`)")
    )
    args = parser.parse_args()

    # Read credentials
    if not os.path.isfile(args.credential_file):
        raise IOError(
            "Credential file not found at location: %s. "
            "You can specify a custom location with the --credentials flag "
            % args.credential_file
        )
    print("Reading submission server credentials: %s" % args.credential_file)
    with open(args.credential_file, 'r') as f:
        endpoint, username, password = f.read().strip().split('\n')

    # Send report
    send_report_to_disconnect(username, password, endpoint, args.reports)
