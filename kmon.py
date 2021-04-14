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
logging_handler.setFormatter(
    logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')
)
logger.addHandler(logging_handler)


debug = False
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0",
    "Connection": "close",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Upgrade-Insecure-Requests": "1"
}
timeout = 15

if not debug:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def heandler(name, action, revert, success, telegram):
    if (success is False and revert is False) or (success is True and revert is True):
        if name == 'telegram':
            requests.get('https://api.telegram.org/bot{}/sendMessage?chat_id={}&text={}'.format(telegram['ttoken'], telegram['tuserid'], action))


def check_ping(hostname):
    response = os.system("ping -c 1 -w 2 {} 2>/dev/null 1>&2".format(hostname))
    # and then check the response...
    return response


def check_error(check, ctx, message):
    heandler('telegram', '{}: {}'.format(check['name'], message), revert=check['revert'], success=False, telegram=ctx.obj['config']['telegram'])
    logger.error('[{}] {}'.format(check['name'], message))


@click.group()
@click.option('--config', '-c', envvar='CONFIGFILENAME', required=False, help="Config File Name", default="config.yaml")
@click.pass_context
def cli(ctx, config):
    ctx.ensure_object(dict)
    file = open(r'{}/{}'.format(os.path.abspath(os.path.dirname(sys.argv[0])), config))
    ctx.obj['config'] = yaml.load(file, Loader=yaml.FullLoader)


@click.option('--name', '-n', required=False, multiple=True, help="check name")
@cli.command()
@click.pass_context
def run(ctx, name):

    # проходимся по всем проверкам
    for check in ctx.obj['config']['checks']:
        res = None
        # если имя проверки указаны через агрументы то работаем только с ними
        if (len(name) > 0 and check['name'] in name) or len(name) == 0:

            # revert меняет значение проверки, если проверка
            # завершилась неудачей это считается ОК или наоборот
            try:
                check['revert']
            except Exception as e:
                logger.error("Exception: {}", e)
                check['revert'] = False

            if 'url' in check.keys():
                try:
                    res = requests.get(check['url'], headers=headers, timeout=timeout, verify=False, allow_redirects=False)
                except Exception as e:
                    message = "url: {}".format(e)
                    check_error(check=check, ctx=ctx, message=message)

            # http code check #
            if 'status_code' in check.keys():
                try:
                    if str(res.status_code) == str(check['status_code']):
                        message = "Status_code: [{}]".format(res.status_code)
                        logger.info('[{}] {}'.format(check['name'], message))
                    else:
                        message = "Status_code: [{}]".format(res.status_code)
                        heandler('telegram', message, revert=check['revert'], success=False, telegram=ctx.obj['config']['telegram'])
                        logger.error('[{}] {}'.format(check['name'], message))
                    if res.status_code == 302:
                        print("{} Redireced to: {}".format(check['url'], res.headers['Location']))
                except Exception as e:
                    message = "status_code: {}".format(e)
                    check_error(check=check, ctx=ctx, message=message)

            # load time check #
            if 'load_time' in check.keys():
                try:
                    if float(res.elapsed.total_seconds()) < float(check['load_time']):
                        message = "Load_time: [{}]".format(str(res.elapsed.total_seconds()))
                        logger.info('[{}] {}'.format(check['name'], message))
                    else:
                        message = "Load_time: [{}]".format(str(res.elapsed.total_seconds()))
                        heandler('telegram', '{}: {}'.format(check['name'], message), revert=check['revert'], success=False, telegram=ctx.obj['config']['telegram'])
                        logger.error('[{}] {}'.format(check['name'], message))
                except Exception as e:
                    message = "load_time: {}".format(e)
                    check_error(check=check, ctx=ctx, message=message)

            # check context #
            if 'search' in check.keys():
                try:
                    if re.search(check['search'], res.text):
                        message = "Search: [{}]".format(check['search'])
                        heandler('telegram', '{}: {}'.format(check['name'], message), revert=check['revert'], success=True, telegram=ctx.obj['config']['telegram'])
                        logger.info('[{}] {}'.format(check['name'], message))
                    else:
                        message = "Search: [{}]".format(check['search'])
                        heandler('telegram', '{}: {}'.format(check['name'], message), revert=check['revert'], success=False, telegram=ctx.obj['config']['telegram'])
                        logger.error('[{}] {}'.format(check['name'], message))
                except Exception as e:
                    message = "search: {}".format(e)
                    check_error(check=check, ctx=ctx, message=message)

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
                        message = "SSL EXPIRE  [{}]".format(notAfter)
                        heandler('telegram', '{}: {}'.format(check['name'], message), revert=check['revert'], success=False, telegram=ctx.obj['config']['telegram'])
                        logger.error('[{}] {}'.format(check['name'], message))
                    else:
                        message = "SSL EXPIRE: [{}]".format(notAfter)
                        logger.info('[{}] {}'.format(check['name'], message))

                    if subject != check['host']:
                        message = "SSL SUBJECT:"
                        heandler('telegram', '{}: {}'.format(check['name'], message), revert=check['revert'], success=False, telegram=ctx.obj['config']['telegram'])
                        logger.error('[{}] {}'.format(check['name'], message))
                    else:
                        message = "SSL SUBJECT: [{}]".format(subject)
                        logger.info('[{}] {}'.format(check['name'], message))

                except Exception as e:
                    message = "SSL CHECK: {}".format(e)
                    check_error(check=check, ctx=ctx, message=message)

            # ICMP (ping) server check #
            if 'icmp' in check.keys():
                if check['icmp']:
                    ping_status = check_ping(check['host'])
                    if ping_status == 0:
                        message = "ICMP: [{}]".format(ping_status)
                        logger.info('[{}] {}'.format(check['name'], message))
                    else:
                        message = "ICMP: [{}]".format(ping_status)
                        heandler('telegram', '{}: {}'.format(check['name'], message), revert=check['revert'], success=False, telegram=ctx.obj['config']['telegram'])
                        logger.error('[{}] {}'.format(check['name'], message))

            # ToDo Shell script run and check exit code
            if 'shell' in check.keys():
                try:
                    command_process = subprocess.Popen(
                        "ssh -o StrictHostKeyChecking=no -o LogLevel=quiet {user}@{host} {cmd}".format(host=check['host'], cmd=check['shell']['cmd'], user=check['shell']['user']),
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )

                    stderr = command_process.stderr.read().decode("utf-8")
                    exit_code = command_process.returncode

                    if exit_code > 0:
                        message = "SHELL: $?:[{code}] ERR:[{stderr}]".format(code=exit_code, stderr=stderr)
                        heandler('telegram', '{}: {}'.format(check['name'], message), revert=check['revert'], success=False, telegram=ctx.obj['config']['telegram'])
                        logger.error('[{}] {}'.format(check['name'], message))
                    else:
                        message = "SHELL: $?:[{code}]".format(code=exit_code)
                        logger.info('[{}] {}'.format(check['name'], message))
                except Exception as e:
                    message = "SHELL: {}".format(e)
                    check_error(check=check, ctx=ctx, message=message)


if __name__ == "__main__":
    cli()
