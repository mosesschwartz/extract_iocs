import os

from extract_iocs import extract_iocs


def test_apt28_report():
    """."""
    expected_output = {'md5': ['8B92FE86C5B7A9E34F433A6FBAC8BC3A', 'EAD4EC18EBCE6890D20757BB9F5285B1', '3B0ECD011500F61237C205834DB0E13A', '8C4FA713C5E2B009114ADDA758ADC445', '5882FDA97FDF78B47081CC4105D44F7C', '9EEBFEBE3987FEC3C395594DC57A0C4C', '48656A93F9BA39410763A2196AABC67F', 'DA2A657DC69D7320F2FFC87013F257AD', '272F0FDE35DBDFCCBCA1E33373B3570D', '791428601AD12B9230B9ACE4F2138713', '1259C4FE5EFD9BF07FC4C78466F2DD09'], 'sha1': [], 'sha256': [], 'ipv4': [], 'url': [], 'domain': ['msdn.microsoft.com', 'rnil.am', 'novinite.com', 'police.ge', 'nshq.nato.int', 'login-osce.org', 'online.co.uk', 'baltichost.org', 'kavkazcentr.info', 'voiceofrussia.com', 'qov.hu.com', 'www.kam.lt', 'adobeincorp.com', 'natoexhibition.org', 'uropa.eu', 'mail.ru', 'mia.ge.gov', 'mail.gov.pl', 'windous.kz', 'fireeye.com', 'mail.q0v.pl', 'wind0ws.kz', 'www.freedomhouse.org', 'standartnevvs.com', 'poczta.mon.gov.pl', 'www.nytimes.com', 'nato.nshq.in', 'standartnews.com', 'adawareblock.com', 'q0v.pl', 'kavkazcenter.com', 'mia.gov.ge', 'poczta.mon.q0v.pl', 'www.mil.ee', 'novinitie.com', 'www.upi.com', 'n0vinite.com', 'rt.com', 'malware.prevenity.com', 'ae.norton.com', 'windows-updater.com', 'www.fireeye.com', 'natoexhibitionff14.com'], 'email': ['dr.house@wind0ws.kz', 'nato_pop@mail.ru', 'nato_smtp@mail.ru', 'lisa.cuddy@wind0ws.kz', 'info@fireeye.com']}

    with open(os.path.abspath(os.path.join(os.path.dirname(__file__), "./samples/apt28report.txt"))) as apt28:
        iocs = extract_iocs.extract_iocs(apt28.read())

        assert len(iocs) == len(expected_output)

        print(iocs)
        
        for indicator_type in iocs:
            # create sets for the actual and expected values for this indicator type
            actual_set = set(iocs[indicator_type])
            expected_set = set(expected_output[indicator_type])

            # make sure the actual and expected sets match
            try:
                assert len(actual_set - expected_set) == 0
            except AssertionError as e:
                print(actual_set - expected_set)
                raise
            try:
                assert len(expected_set - actual_set) == 0
            except AssertionError as e:
                print(expected_set - actual_set)
                raise


def test_simple_report():
    """."""
    expected_output = {'md5': ['E2021791428601AD12B9230B9ACE4F21'], 'sha1': ['B2021791428601AD12B9230B9ACE4F219ACE4F21'], 'sha256': ['2011201120112012201220122012201220122013201320132013201320132013'], 'url': [], 'ipv4': ['1.2.3.4'], 'domain': ['example.org', 'example.com', 'gmail.org'], 'email': ['bad@gmail.org']}
    # 'url': ['http://example.com', 'https://example.com', 'http://example.com/test/bingo.php', 'ftp://example.com']

    with open(os.path.abspath(os.path.join(os.path.dirname(__file__), "./samples/simple.txt"))) as apt28:
        iocs = extract_iocs.extract_iocs(apt28.read())

        assert len(iocs) == len(expected_output)
        
        for indicator_type in iocs:
            # create sets for the actual and expected values for this indicator type
            actual_set = set(iocs[indicator_type])
            expected_set = set(expected_output[indicator_type])

            # make sure the actual and expected sets match
            assert len(actual_set - expected_set) == 0
            assert len(expected_set - actual_set) == 0
