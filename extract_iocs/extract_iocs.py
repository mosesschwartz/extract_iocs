#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Extract IOCs from text.
"""

try:
    import configparser as ConfigParser
except ImportError:
    import ConfigParser
import os
import re

regexes = dict()


def _load_regexes(regex_file_path):
    """."""
    config = ConfigParser.ConfigParser()
    with open(regex_file_path) as f:
        config.readfp(f)

    for ind_type in config.sections():
        try:
            # get the regex for the indicator type
            ind_pattern = config.get(ind_type, 'regex')
        except ConfigParser.NoOptionError as e:
            continue

        # add the regex
        if ind_pattern:
            # append the host regex to the end of the email address regex
            if ind_type == 'email':
                ind_pattern = ind_pattern + config['host']['regex']
            ind_regex = re.compile(ind_pattern)
            regexes[ind_type] = ind_regex


def extract_iocs(text):
    '''Extract IOCs from input text. Returns a dict:
        {'md5' : ['list of MD5s'],
        'sha1' : ['list of SHA1s'],
        'sha256' : ['list of SHA256s'],
        'ipv4' : ['list of IPs'],
        'domain' : ['list of domains'],
        'email' : ['list of email addresses']}
    '''
    text = text.lower() # convert to lower case for simplicity
    iocs = _extract_iocs(text)
    return iocs


def already_found(h, already_found_hashes):
    '''
    checks to see if a hash is a subset or superset of the hashes in the
    already_found_hashes list. This is totally imperfect, but it seems to do
    a good job of minimizing incorrectly-identified hashes.
    '''
    if (True not in [h in foundhash for foundhash in already_found_hashes] and
        True not in [foundhash in h for foundhash in already_found_hashes
                     if len(foundhash) >= 32]):
        return False
    else:
        return True


def _extract_iocs(text, confidence_modifier=0):
    iocs = {'md5': [],
            'sha1': [],
            'sha256': [],
            'ipv4': [],
            'url': [],
            'domain': [],
            'email': []}

    already_found_hashes = list()

    # sha256
    for match in re.finditer(regexes['sha256'], text):
        h = match.string[match.start():match.end()].upper()
        if not already_found(h, already_found_hashes):
            iocs['sha256'].append(h)
            already_found_hashes.append(h)

    # sha1
    for match in re.finditer(regexes['sha1'], text):
        h = match.string[match.start():match.end()].upper()
        if not already_found(h, already_found_hashes):
            iocs['sha1'].append(h)
            already_found_hashes.append(h)

    # md5
    for match in re.finditer(regexes['md5'], text):
        h = match.string[match.start():match.end()].upper()
        if not already_found(h, already_found_hashes):
            iocs['md5'].append(h)

    # ipv4
    for match in re.finditer(regexes['ipv4'], text):
        ip = match.string[match.start():match.end()]
        # strip brackets:
        ip = ip.replace('[', '').replace(']', '')
        # strip leading 0s:
        ip = '.'.join([str(int(x)) for x in ip.split('.')])
        iocs['ipv4'].append(ip)

    # host
    for match in re.finditer(regexes['host'], text):
        confidence = 0 + confidence_modifier
        if '[.]' in match.string[match.start():match.end()]:
            # brackets around .s is a VERY strong signal...
            confidence += 20
        if '://' in match.string[match.start() - 3:match.start()]:
            # if there's a :// before the match, we're pretty sure
            confidence += 10
        if match.string[match.start() - 7:match.start() - 3] in ['ttp', 'tps', 'ftp']:
            # if there's something like http(s) or ftp, confidence++
            confidence += 10
        if match.string[match.end():match.end() + 1] in ['/', ':']:
            # followed by slash or colon? confidence++
            confidence += 10
        if match.string[match.end() - 2:match.end() + 1] in ['tmp', 'cab', 'htm', 'cgi', 'asp',
                                             'gif', 'jpg', 'doc', 'php', 'png']:
            # wait, are these file names?
            confidence -= 5
        if match.string[match.end() - 3:match.end()] in ['zip', 'mov']:
            # okay, these are legit, but it might be a file name....
            confidence -= 5
        if '@' in match.string[match.start() - 1:match.start()]:
            # looks like an email address!
            confidence += 10
        if match.end() - match.start() < 9:
            # unusually short...
            confidence -= 5
        if confidence >= 0:
            iocs['domain'].append(match.string[match.start():match.end()].replace('[','').replace(']',''))

    # email
    for match in re.finditer(regexes['email'], text):
        iocs['email'].append(match.string[match.start():match.end()].replace('[','').replace(']',''))

    # Remove duplicates
    for ioc_type, ioc_list in iocs.items():
        iocs[ioc_type] = list(set(ioc_list))
    return iocs


# load the regexes
_load_regexes(os.path.abspath(os.path.join(os.path.dirname(__file__), "./data/regexes.ini")))
