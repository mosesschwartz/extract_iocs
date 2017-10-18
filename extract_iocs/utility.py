#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Utility functions for parsing (Indicators of Compromise) from text."""


def calculate_domain_score(match, confidence):
    """Calculate the confidence score of a domain."""
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
    if match.string[match.end() - 2:match.end() + 1] in ['tmp', 'cab', 'htm', 'cgi', 'asp', 'gif', 'jpg', 'doc', 'php', 'png']:
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

    return confidence
