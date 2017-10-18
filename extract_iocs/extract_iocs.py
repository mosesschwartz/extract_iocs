#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Extract IOCs from text."""

try:
    import configparser as ConfigParser
except ImportError:
    import ConfigParser
import os
import re

from .utility import calculate_domain_score

indicator_regexes = dict()
removed_indicator_types = list()


def _load_regexes(regex_file_path):
    """."""
    config = ConfigParser.ConfigParser()
    # read the config file
    with open(regex_file_path) as f:
        config.readfp(f)

    # keep track of indicator orders
    temp_indicator_order = {}
    unordered_types = list()

    # initialize the indicator order
    indicator_order = ['' for section in config.sections()]

    for ind_type in config.sections():
        try:
            # get the regex for the indicator type
            ind_pattern = config.get(ind_type, 'regex')
        except ConfigParser.NoOptionError as e:
            continue

        # add the regex
        if ind_pattern:
            # append the domain regex to the end of the email address regex
            if ind_type == 'email':
                ind_pattern = ind_pattern + config.get('domain', 'regex')

            ind_regex = re.compile(ind_pattern)
            indicator_regexes[ind_type] = ind_regex

        # track the indicator_order
        try:
            ind_order = config.get(ind_type, 'order')
        except ConfigParser.NoOptionError as e:
            # add the indicator type without an order
            unordered_types.append(ind_type)
        else:
            # keep track of the index at which the indicator type should be parsed
            temp_indicator_order[ind_type] = int(ind_order)

        # check to see if this kind of indicator should be removed once it is found
        try:
            remove = config.get(ind_type, 'remove')
        except ConfigParser.NoOptionError as e:
            pass
        else:
            if remove:
                removed_indicator_types.append(ind_type)

    # add all of the ordered indicator types
    for indicator_type in temp_indicator_order:
        indicator_order[temp_indicator_order[indicator_type]] = indicator_type
    # add all of the unordered indicator types
    indicator_order.extend(unordered_types)
    # remove any blank entries
    indicator_order = [order for order in indicator_order if order != '']
    return indicator_order


# load the regexes
indicator_order = _load_regexes(os.path.abspath(os.path.join(os.path.dirname(__file__), "./data/regexes.ini")))


def extract_iocs(text, confidence_modifier=0):
    """Extract IOCs from input text.

    Returns a dict:
        {'md5' : ['list of MD5s'],
        'sha1' : ['list of SHA1s'],
        'sha256' : ['list of SHA256s'],
        'ipv4' : ['list of IPs'],
        'domain' : ['list of domains'],
        'email' : ['list of email addresses']}
    """
    text = text.lower()  # convert to lower case for simplicity
    iocs = _extract_iocs(text, confidence_modifier)
    return iocs


def _already_found(h, already_found_hashes):
    """
    Checks to see if a hash is a subset or superset of the hashes in the
    already_found_hashes list. This is totally imperfect, but it seems to do
    a good job of minimizing incorrectly-identified hashes.
    """
    if (True not in [h in foundhash for foundhash in already_found_hashes] and
        True not in [foundhash in h for foundhash in already_found_hashes
                     if len(foundhash) >= 32]):
        return False
    else:
        return True


def _extract_iocs(text, confidence_modifier):
    iocs = {'md5': [],
            'sha1': [],
            'sha256': [],
            'ipv4': [],
            'url': [],
            'domain': [],
            'email': []}

    already_found_hashes = list()

    for indicator_type in indicator_order:
        # parse all of the indicators of the given type from the text
        for match in re.finditer(indicator_regexes[indicator_type], text):
            # handle file hashes
            if indicator_type in ['md5', 'sha1', 'sha256']:
                hash_ = match.string[match.start():match.end()].upper()
                if not _already_found(hash_, already_found_hashes):
                    iocs[indicator_type].append(hash_)
                    if indicator_type is not "md5":
                        already_found_hashes.append(hash_)
            # handle ipv4 addresses
            elif indicator_type == "ipv4":
                ip = match.string[match.start():match.end()]
                # strip leading 0s
                ip = '.'.join([str(int(x)) for x in ip.split('.')])
                iocs['ipv4'].append(ip)
            elif indicator_type == "domain":
                confidence = calculate_domain_score(match, confidence_modifier)
                if confidence >= 0:
                    iocs['domain'].append(match.string[match.start():match.end()].replace('[', '').replace(']', ''))
            # handle email addresses
            elif indicator_type == "email":
                iocs['email'].append(match.string[match.start():match.end()].replace('[', '').replace(']', ''))
            elif indicator_type == "url":
                # support for urls coming soon
                pass
            else:
                print("Unknown indicator type: {}".format(indicator_type))

            # if appropriate, remove the indicator from the text
            if indicator_type in removed_indicator_types:
                text = text.replace(match.string[match.start():match.end()], "")

    # Remove duplicates
    for ioc_type, ioc_list in iocs.items():
        iocs[ioc_type] = list(set(ioc_list))
    return iocs
