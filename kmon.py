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
import click
import logging
import subprocess

# logger
logger = logging.getLogger('kmon')
logger.setLevel(logging.DEBUG)
logging_handler = logging.StreamHandler()
logging_handler.setFormatter(logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s'))
logger.addHandler(logging_handler)


debug = False
headers = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0","Connection":"close","Accept-Language":"en-US,en;q=0.5","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Upgrade-Insecure-Requests":"1"}
timeout = 15

if not debug:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def heandler(name, action, revert, success, telegram):
    if (success == False and revert == False) or (success == True and revert == True):
        if name == 'telegram':
            requests.get('https://api.telegram.org/bot{}/sendMessage?chat_id={}&text={}'.format(telegram['ttoken'], telegram['tuserid'], action))


def check_ping(hostname):
    response = os.system("ping -c 1 -w 2 {} 2>/dev/null 1>&2".format(hostname))
    # and then check the response...
    return response


@click.group()
@click.option('--config', '-c', envvar='CONFIGFILENAME', required=False, help="Config File Name", default="config.yaml")
@click.pass_context
def cli(ctx, config):
    ctx.ensure_object(dict)
    file = open(r'{}/{}'.format( os.path.abspath(os.path.dirname(sys.argv[0])), config ))
    ctx.obj['config'] = yaml.load(file, Loader=yaml.FullLoader)


@click.option('--name', '-n', required=False, multiple=True, help="check name")
@cli.command()
@click.pass_context
def run(ctx, name):

    # проходимся по всем проверкам
    for check in ctx.obj['config']['checks']:

        # если имя проверки указаны через агрументы то работаем только с ними
        if (len(name) > 0 and check['name'] in name) or len(name) == 0:

            # revert меняет значение проверки, если проверка  
            # завершилась неудачей это считается ОК или наоборот
            try:
                check['revert']
            except:
                check['revert'] = False

            if 'url' in check.keys():
                res = requests.get(check['url'], headers=headers, timeout=timeout, verify=False, allow_redirects=False)

            # http code check #
            if 'status_code' in check.keys():
                if str(res.status_code) == str(check['status_code']):
                    message = "Status_code: [{}]".format(res.status_code)
                    logger.info('{} {}'.format(check['name'], message))
                else:
                    message = "Status_code: [{}]".format(res.status_code)
                    heandler('telegram', message, revert=check['revert'], success=False,  telegram=ctx.obj['config']['telegram'])
                    logger.error('{} {}'.format(check['name'], message))
                if res.status_code == 302:
                    print("{} Redireced to: {}".format(check['url'], res.headers['Location']))

            # load time check #
            if 'load_time' in check.keys():
                if float(res.elapsed.total_seconds()) < float(check['load_time']):
                    message = "Load_time: [{}]".format(str(res.elapsed.total_seconds()))
                    logger.info('{} {}'.format(check['name'], message))
                else:
                    message = "Load_time: [{}]".format(str(res.elapsed.total_seconds()))
                    heandler('telegram', '{}: {}'.format(check['name'], message), revert=check['revert'], success=False,  telegram=ctx.obj['config']['telegram'])
                    logger.error('{} {}'.format(check['name'], message))

            # check context #
            if 'search' in check.keys():
                if re.search(check['search'], res.text):
                    message = "Search: [{}]".format(check['search'])
                    heandler('telegram', '{}: {}'.format(check['name'], message), revert=check['revert'], success=True,  telegram=ctx.obj['config']['telegram'])
                    logger.info('{} {}'.format(check['name'], message))
                else:
                    message = "Search: [{}]".format(check['search'])
                    heandler('telegram', '{}: {}'.format(check['name'], message), revert=check['revert'], success=False,  telegram=ctx.obj['config']['telegram'])
                    logger.error('{} {}'.format(check['name'], message))

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
                        message = "SSL EXPIRE  ["+notAfter+"]"
                        heandler('telegram', '{}: {}'.format(check['name'], message), revert=check['revert'], success=False,  telegram=ctx.obj['config']['telegram'])
                    else:
                        message = "SSL EXPIRE: [{}]".format(notAfter)
                        logger.info('{} {}'.format(check['name'], message))

                    if subject != check['host']:
                        message = "SSL SUBJECT:"
                        heandler('telegram', '{}: {}'.format(check['name'], message), revert=check['revert'], success=False,  telegram=ctx.obj['config']['telegram'])
                        logger.error('{} {}'.format(check['name'], message))
                    else:
                        message = "SSL SUBJECT: [{}]".format(subject)
                        logger.info('{} {}'.format(check['name'], message))

                except Exception as e:
                    message = "SSL CHECK: {}".format(e)
                    logger.error('{} {}'.format(check['name'], message))

            # ICMP (ping) server check #
            if 'icmp' in check.keys():
                if check['icmp']:
                    ping_status = check_ping(check['host'])
                    if ping_status == 0:
                        message = "ICMP: [{}]".format(ping_status)
                        logger.info('{} {}'.format(check['name'], message))
                    else:
                        message = "ICMP: [{}]".format(ping_status)
                        heandler('telegram', '{}: {}'.format(check['name'], message), revert=check['revert'], success=False,  telegram=ctx.obj['config']['telegram'])
                        logger.error('{} {}'.format(check['name'], message))

            #ToDo Shell script run and check exit code
            if 'shell' in check.keys():

                command_process = subprocess.Popen(
                    "ssh -o StrictHostKeyChecking=no -o LogLevel=quiet {user}@{host} {cmd}".format(host=check['host'], cmd=check['shell']['cmd'], user=check['shell']['user']),
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )

                stderr=command_process.stderr.read().decode("utf-8") 
                #stdout=command_process.stdout.read().decode("utf-8") 
                command_output = command_process.communicate()[0]
                exit_code = command_process.returncode
 
                if exit_code > 0:
                    message = "SHELL: $?:[{code}] CMD:[{cmd}] ERR:[{stderr}]".format(code=exit_code, stderr=stderr, cmd=check['shell']['cmd'])
                    heandler('telegram', '{}: {}'.format(check['name'], message), revert=check['revert'], success=False,  telegram=ctx.obj['config']['telegram'])
                    logger.error('{} {}'.format(check['name'], message))
                else:
                    #message = "SHELL: EXIT_CODE [{code}] OUT:[{stdout}]".format(code=exit_code, stdout=stdout)
                    message = "SHELL: $?:[{code}] CMD:[{cmd}]".format(code=exit_code, cmd=check['shell']['cmd'])
                    logger.info('{} {}'.format(check['name'], message))


if __name__ == "__main__":
    cli()
