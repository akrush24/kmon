#!/usr/bin/python3
import requests, yaml

from datetime import datetime, date, time, timedelta
import ssl
import OpenSSL
import pytz
import socket
import re
from urllib.parse import urlparse
import urllib.request, json
import email.message
import smtplib
from urllib.request import Request, urlopen, ssl, socket
from urllib.error import URLError, HTTPError

debug = False
headers = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0","Connection":"close","Accept-Language":"en-US,en;q=0.5","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Upgrade-Insecure-Requests":"1"}
timeout = 15

if not debug:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

file = open(r'sites.yaml')
sites = yaml.load(file, Loader=yaml.FullLoader)

def layout(res, check):
    print(datetime.now(), site['http'], res.status_code, float(res.elapsed.total_seconds()), check)

def action(action):
    print("AXTUNG")

now = datetime.now(pytz.utc)

for site in sites:
    res = requests.get(site['http'], headers=headers, timeout=timeout, verify=False, allow_redirects=False)

    # http code check #
    if 'status_code' in site.keys():
        if str(res.status_code) == str(site['status_code']):
            check = "Status_code:OK"
        else:
            check = "Status_code:ERROR"
            if 'search' in site.keys():
                action(site['search'])
        layout(res, check)

    # load time check #
    if 'load_time' in site.keys():
        if float(res.elapsed.total_seconds()) < float(site['load_time']):
            check = "Load_time:OK"
        else:
            check = "Load_time:ERROR"
            if 'search' in site.keys():
                action(site['search'])
        layout(res, check)

    # check context #
    if 'search' in site.keys():
        if re.search(site['search'], res.text):
            check = "Search:OK"
        else:
            check = "Search:ERROR"
            if 'search' in site.keys():
                action(site['search'])
        layout(res, check)

    # checl ssl expiration @
    if 'min_ssl_expiry_days' in site.keys():
        port = '443'
        context = ssl.create_default_context()
        with socket.create_connection((site['host'], port)) as sock:
            with context.wrap_socket(sock, server_hostname=site['host']) as ssock:
                notAfter = datetime.strptime(ssock.getpeercert()['notAfter'], r"%b %d %H:%M:%S %Y %Z").replace(tzinfo=pytz.UTC)
                subject = ssock.getpeercert()['subject'][0][0][1]
        
        ssl_check_date = datetime.now() + timedelta(days=site['min_ssl_expiry_days'])
        if ssl_check_date.replace(tzinfo=pytz.UTC) > notAfter.replace(tzinfo=pytz.UTC):
            check = "SSL EXPIRE ERROR"
        else:
            check = "SSL EXPIRE:OK"
        layout(res, check)
        if subject != site['host']:
            check = "SSL SUBJECT:ERROR"
        else:
            check = "SSL SUBJECT:OK"
        layout(res, check)

    # check work in http res
    # TO DO
