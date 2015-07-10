import sys
sys.path.insert(0, '..')
import extract_iocs

expected_output = {'domain': ['malware.prevenity.com', 'n0vinite.com', 'domainkavkazcentr.infornil.am', 'windous.kz', 'wind0ws.kz', 'poczta.mon.q0v.pl', 'www.kam.lt', 'q0v.pl', 'uropa.eu', 'mail.gov.pl', 'natoexhibition.org', 'mail.ru', 'novinitie.com', 'ae.norton.com', 'mia.ge.gov', 'www.mil.ee', 'poczta.mon.gov.pl', 'mia.gov.ge', 'kavkazcenter.com', 'qov.hu.comq0v.pl', 'login-osce.org', 'www.nytimes.com', 'domainnato.nshq.innatoexhibitionff14.com', 'smigroup-online.co.uk', 'www.freedomhouse.org', 'rt.com', 'rnil.am', 'baltichost.org', 'www.upi.com', 'nshq.nato.int', 'msdn.microsoft.com', 'mail.q0v.plpoczta.mon.q0v.pl', 'kavkazcentr.info', 'windows-updater.com', 'www.fireeye.com', 'mail.q0v.pl', 'voiceofrussia.com', 'natoexhibitionff14.com', 'nato.nshq.in', 'standartnevvs.com', 'mail.ru.al', 'police.ge', 'fireeye.com', 'standartnews.com', 'novinite.com', 'domainstandartnevvs.com', 'online.co.uk', 'qov.hu.com', 'adobeincorp.com', 'adawareblock.com'], 'sha1': [], 'url': [], 'ipv4': [], 'sha256': ['2011201120112012201220122012201220122013201320132013201320132013'], 'email': ['nato_smtp@mail.ru', 'nato_pop@mail.ru', 'nato_pop@mail.ru.al', 'info@fireeye.com', 'lisa.cuddy@wind0ws.kz', '(@mia.gov.ge', 'dr.house@wind0ws.kz'], 'md5': ['8C4FA713C5E2B009114ADDA758ADC445', '3B0ECD011500F61237C205834DB0E13A', 'E2021791428601AD12B9230B9ACE4F21', '791428601AD12B9230B9ACE4F2138713', '5882FDA97FDF78B47081CC4105D44F7C', 'DA2A657DC69D7320F2FFC87013F257AD', '48656A93F9BA39410763A2196AABC67F', '9EEBFEBE3987FEC3C395594DC57A0C4C', 'E228C4FA713C5E2B009114ADDA758ADC', '18B92FE86C5B7A9E34F433A6FBAC8BC3', '8B92FE86C5B7A9E34F433A6FBAC8BC3A', 'E5882FDA97FDF78B47081CC4105D44F7', 'EAD4EC18EBCE6890D20757BB9F5285B1', 'E9EEBFEBE3987FEC3C395594DC57A0C4', '1259C4FE5EFD9BF07FC4C78466F2DD09', '272F0FDE35DBDFCCBCA1E33373B3570D', 'E171819DA2A657DC69D7320F2FFC8701']}

with open('apt28report.txt') as apt28:
    iocs = extract_iocs.extract_iocs(apt28.read())
    if iocs == expected_output:
        print 'Sad test passed'

