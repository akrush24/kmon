#!/usr/bin/python3
import requests
import yaml

import pytz
import socket
import re
import ssl
import sys
import os
from datetime import datetime, timedelta


debug = False
headers = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0","Connection":"close","Accept-Language":"en-US,en;q=0.5","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Upgrade-Insecure-Requests":"1"}
timeout = 15

if not debug:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def layout(name, check):
    print("[{}] {} {}".format(datetime.now(), name, check))

def heandler(name, action):
    if name == 'telegram':
        requests.get('https://api.telegram.org/bot{}/sendMessage?chat_id={}&text={}'.format(config['telegram']['ttoken'], config['telegram']['tuserid'], action))

def check_ping(hostname):
    response = os.system("ping -c 1 -w 2 {} 2>/dev/null 1>&2".format(hostname))
    # and then check the response...
    return response

def main():
    file = open(r'{}/config.yaml'.format(os.path.abspath(os.path.dirname(sys.argv[0]))))
    config = yaml.load(file, Loader=yaml.FullLoader)

    for site in config['checks']:
        
        if 'url' in site.keys():
            res = requests.get(site['url'], headers=headers, timeout=timeout, verify=False, allow_redirects=False)

        # http code check #
        if 'status_code' in site.keys():
            if str(res.status_code) == str(site['status_code']):
                check = "Status_code:OK [{}]".format(res.status_code)
            else:
                check = "Status_code:ERROR [{}]".format(res.status_code)
                heandler('telegram', site['url']+", "+check)
            if res.status_code == 302:
                print("{} Redireced to: {}".format(site['url'], res.headers['Location']))
            layout(site['name'], check)

        # load time check #
        if 'load_time' in site.keys():
            if float(res.elapsed.total_seconds()) < float(site['load_time']):
                check = "Load_time:OK [{}]".format(str(res.elapsed.total_seconds()))
            else:
                check = "Load_time:ERROR [{}]".format(str(res.elapsed.total_seconds()))
                heandler('telegram', site['host']+", "+check)
            layout(site['name'], check)

        # check context #
        if 'search' in site.keys():
            if re.search(site['search'], res.text):
                check = "Search:OK"
            else:
                check = "Search:ERROR"
                heandler('telegram', site['url']+", "+check)
            layout(site['name'], check)

        # checl ssl expiration #
        if 'min_ssl_expiry_days' in site.keys():
            port = '443'
            context = ssl.create_default_context()
            if (not os.environ.get('PYTHONHTTPSVERIFY', '') and getattr(ssl, '_create_unverified_context', None)):
                ssl._create_default_https_context = ssl._create_unverified_context
            try:
                with socket.create_connection((site['host'], port)) as sock:
                    with context.wrap_socket(sock, server_hostname=site['host']) as ssock:
                        notAfter = datetime.strptime(ssock.getpeercert()['notAfter'], r"%b %d %H:%M:%S %Y %Z").replace(tzinfo=pytz.UTC)
                        subject = ssock.getpeercert()['subject'][0][0][1]
                
                ssl_check_date = datetime.now() + timedelta(days=site['min_ssl_expiry_days'])
                if ssl_check_date.replace(tzinfo=pytz.UTC) > notAfter.replace(tzinfo=pytz.UTC):
                    check = "SSL EXPIRE ERROR ["+notAfter+"]"
                    heandler('telegram', site['host']+", "+check)
                else:
                    check = "SSL EXPIRE:OK [{}]".format(notAfter)
                    layout(site['name'], check)
                
                if subject != site['host']:
                    check = "SSL SUBJECT:ERROR"
                    heandler('telegram', site['host']+", "+check)
                else:
                    check = "SSL SUBJECT:OK [{}]".format(subject)
                    layout(site['name'], check)
                
            except Exception as e:
                check = "SSL CHECK ERROR: {}".format(e)
                layout(site['name'], check)

        # ICMP (ping) server check #
        if 'icmp' in site.keys():
            if site['icmp']:
                ping_status = check_ping(site['host'])
                if ping_status == 0:
                    check = "ICMP:OK"
                else:
                    check = "ICMP:ERROR [{}]".format(ping_status)
                    heandler('telegram', "{}, {}".format(site['host'],check))
                layout(site['name'], check)



if __name__ == "__main__":
    main()
