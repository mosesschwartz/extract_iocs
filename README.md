extract_iocs is a Python module that extracts indicators of compromise (IOCs),
including domain names, IPv4 addresses, email addresses, and hashes, from
text. It uses some huge and ugly regexes, has special handling to identify
domain names with a relatively low false-positive rate, and does some magic to
try to extract IOCs across line breaks.

This script was inspired by and initially based on Stephen Brannon's
IOCextractor (https://github.com/stephenbrannon/IOCextractor), but turned into
a complete rewrite. extract_iocs provides no GUI and does not support any kind
of analyst workflow. It is intended to be used for triage or automation
purposes where a relatively high FP rate (as well as the occational false
negative) are acceptable.
