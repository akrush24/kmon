#!/usr/bin/python3
import requests, yaml

from datetime import datetime, date, time
import ssl
import OpenSSL

debug = False
headers = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0","Connection":"close","Accept-Language":"en-US,en;q=0.5","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Upgrade-Insecure-Requests":"1"}
timeout = 15

if not debug:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

file = open(r'sites.yaml')
sites = yaml.load(file, Loader=yaml.FullLoader)

def get_SSL_Expiry_Date(host, port):
    cert = ssl.get_server_certificate((host, 443))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    print(datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'))

def layout(res, check):
    print(datetime.now(), site['http'], res.status_code, float(res.elapsed.total_seconds()), check)

def handler(self, parameter_list):
    pass

for site in sites:
    res = requests.get(site['http'], headers=headers, timeout=timeout, verify=False, allow_redirects=False)
    # http code check
    if 'status_code' in site.keys():
        if str(res.status_code) == str(site['status_code']):
            check = "status_code:OK"
        else:
            check = "status_code:ERROR"
        layout(res, check)
    # load time check
    if 'load_time' in site.keys():
        if float(res.elapsed.total_seconds()) < float(site['load_time']):
            check = "load_time:OK"
        else:
            check = "load_time:ERROR"
        layout(res, check)
    # checl ssl expiration
    if 'min_ssl_expiry_days' in site.keys():
        get_SSL_Expiry_Date(site['host'], 443)

    # check work in http res
    # TO DO
