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
file = open(r'{}/config.yaml'.format(os.path.abspath(os.path.dirname(sys.argv[0]))))
config = yaml.load(file, Loader=yaml.FullLoader)
if not debug:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def layout(name, check):
    print("[{}] {} {}".format(datetime.now(), name, check))

def heandler(name, action, revert, success):
    if (success == False and revert == False) or \
        (success == True and revert == True):
        if name == 'telegram':
            requests.get('https://api.telegram.org/bot{}/sendMessage?chat_id={}&text={}'.format(config['telegram']['ttoken'], config['telegram']['tuserid'], action))

def check_ping(hostname):
    response = os.system("ping -c 1 -w 2 {} 2>/dev/null 1>&2".format(hostname))
    # and then check the response...
    return response

def main():

    for check in config['checks']:

        # переменная меняет значение проверки, если проверка завершилась 
        # неудачей это считается ОК или наоборот
        try:
            check['revert']
        except:
            check['revert'] = False

        if 'url' in check.keys():
            res = requests.get(check['url'], headers=headers, timeout=timeout, verify=False, allow_redirects=False)

        # http code check #
        if 'status_code' in check.keys():
            if str(res.status_code) == str(check['status_code']):
                message = "Status_code:OK [{}]".format(res.status_code)
            else:
                message = "Status_code:ERROR [{}]".format(res.status_code)
                heandler('telegram', check['url']+", "+check)
            if res.status_code == 302:
                print("{} Redireced to: {}".format(check['url'], res.headers['Location']))
            layout(check['name'], message)

        # load time check #
        if 'load_time' in check.keys():
            if float(res.elapsed.total_seconds()) < float(check['load_time']):
                message = "Load_time:OK [{}]".format(str(res.elapsed.total_seconds()))
            else:
                message = "Load_time:ERROR [{}]".format(str(res.elapsed.total_seconds()))
                heandler('telegram', check['host']+", "+check)
            layout(check['name'], message)

        # check context #
        if 'search' in check.keys():
            if re.search(check['search'], res.text):
                message = "Search:OK"
                heandler('telegram', check['name']+", "+message, revert=check['revert'], success=True)
            else:
                message = "Search:ERROR"
                heandler('telegram', check['name']+", "+message, revert=check['revert'], success=False)
            layout(check['name'], message)

        # checl ssl expiration #
        if 'min_ssl_expiry_days' in check.keys():
            port = '443'
            context = ssl.create_default_context()
            if (not os.environ.get('PYTHONHTTPSVERIFY', '') and getattr(ssl, '_create_unverified_context', None)):
                ssl._create_default_https_context = ssl._create_unverified_context
            try:
                with socket.create_connection((check['host'], port)) as sock:
                    with context.wrap_socket(sock, server_hostname=check['host']) as ssock:
                        notAfter = datetime.strptime(ssock.getpeercert()['notAfter'], r"%b %d %H:%M:%S %Y %Z").replace(tzinfo=pytz.UTC)
                        subject = ssock.getpeercert()['subject'][0][0][1]
                
                ssl_check_date = datetime.now() + timedelta(days=check['min_ssl_expiry_days'])
                if ssl_check_date.replace(tzinfo=pytz.UTC) > notAfter.replace(tzinfo=pytz.UTC):
                    message = "SSL EXPIRE ERROR ["+notAfter+"]"
                    heandler('telegram', check['host']+", "+message)
                else:
                    message = "SSL EXPIRE:OK [{}]".format(notAfter)
                    layout(check['name'], message)
                
                if subject != check['host']:
                    message = "SSL SUBJECT:ERROR"
                    heandler('telegram', check['host']+", "+message)
                else:
                    message = "SSL SUBJECT:OK [{}]".format(subject)
                    layout(check['name'], message)
                
            except Exception as e:
                message = "SSL CHECK ERROR: {}".format(e)
                layout(check['name'], message)

        # ICMP (ping) server check #
        if 'icmp' in check.keys():
            if check['icmp']:
                ping_status = check_ping(check['host'])
                if ping_status == 0:
                    message = "ICMP:OK"
                else:
                    message = "ICMP:ERROR [{}]".format(ping_status)
                    heandler('telegram', "{}, {}".format(check['host'], message))
                layout(check['name'], message)



if __name__ == "__main__":
    main()
