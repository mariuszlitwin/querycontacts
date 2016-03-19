'''
querycontacts: query network abuse contacts for a given ip address on
abuse-contacts.abusix.org

Copyright 2013 by abusix GmbH
Author: abusix GmbH
License: GPLv3

'''
import sys
(python_ver, _, _, _, _) = sys.version_info

from dns import resolver
from dns.reversename import from_address as reversename
from dns.name import from_text as dnsname
if python_ver == 3:
    from ipaddress import ip_address
else:
    from ipaddr import IPAddress as ip_address
from ._version import __version__


class ContactFinder(object):

    '''
    Contact Finder
    '''

    def __init__(self, provider='abuse-contacts.abusix.org'):
        '''
        Init

        :param provider: Abuse contact lookup provider
        :type provider: string
        '''
        self.set_provider(provider)
        self.resolver = resolver.get_default_resolver()

    def set_provider(self, provider):
        '''
        set the provider for a specific path

        :param provider: Abuse contact lookup provider
        :type provider: string
        '''
        self.provider = dnsname(provider)

    def find(self, ip):
        '''
        Find the abuse contact for a IP address

        :param ip: IPv4 or IPv6 address to check
        :type ip: string
        
        :returns: emails associated with IP
        :rtype: list
        :returns: none if no contact could be found
        :rtype: None

        :raises: :py:class:`ValueError`: if ip is not properly formatted
        '''
        ip = ip_address(ip)
        rev = reversename(ip.exploded)
        revip, _ = rev.split(3)
        lookup = revip.concatenate(self.provider).to_text()

        contacts = self._get_txt_record(lookup)
        if contacts:
            return contacts.split(',')

    def _get_txt_record(self, name):
        data = []
        try:
            answers = self.resolver.query(name, 'TXT')
        except (resolver.NXDOMAIN, resolver.NoAnswer):
            return

        for answer in answers:
            return ''.join(answer.strings)
