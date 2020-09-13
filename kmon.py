#!/usr/bin/python3
import requests, yaml
from datetime import datetime, date, time

file = open(r'sites.yaml')
sites = yaml.load(file, Loader=yaml.FullLoader)

for site in sites:
    status_code = None
    try:
        res = requests.get(site['http'])
        status_code = res.status_code
    except:
        pass
    if str(status_code) == str(site['status_code']):
        print(datetime.now(), site['name'], status_code, 'OK')
    else:
        print(datetime.now(), site['name'], status_code, 'ERR')

