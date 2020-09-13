#!/usr/bin/python3
import requests, yaml
from datetime import datetime, date, time

file = open(r'sites.yaml')
sites = yaml.load(file, Loader=yaml.FullLoader)

def layout(res, check):
    print(datetime.now(), site['name'], status_code, float(res.elapsed.total_seconds()), check)

def handler(self, parameter_list):
    pass

for site in sites:
    status_code = None
    try:
        res = requests.get(site['http'])
        status_code = res.status_code
    except:
        pass
    # http code check
    if 'status_code' in site.keys():
        if str(status_code) == str(site['status_code']):
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
