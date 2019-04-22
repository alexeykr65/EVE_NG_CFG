#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Configure S-Terra
#
# alexeykr@gmail.com
# coding=utf-8
# import codecs
import paramiko
import scp
import re
import time
import netmiko as nm
import warnings
import logging
import sys
import argparse
import xmltodict
import telnetlib
import pexpect
from netaddr import IPNetwork
warnings.filterwarnings(action='ignore', module='.*paramiko.*')

# FORMATTER = logging.Formatter("'%(asctime)s - %(name)s - %(levelname)s - %(message)s'")


def check_argument_parser(description_argument_parser, epilog_argument_parser):
    parser = argparse.ArgumentParser(description=description_argument_parser, epilog=epilog_argument_parser)
    parser.add_argument('-u', '--unlfile', help='Get UNL file from EVE-NG', dest="unl_file", default='')
#    parser.add_argument('-ca', '--ca', help='Copy CA public Key', dest="ca_cert", action="store_true")
    parser.add_argument('-hi', '--host_ip', help='IP addreses of EVE-NG', dest="host_ip", default='')
    parser.add_argument('-c', '--conf_file', help='Files of configuration', dest="conf_file", default='')
#    parser.add_argument('-ps', '--password', help='Set passwords', dest="password", default='')
    parser.add_argument('-d', '--debug', help='Debug information view(1 - standart, 2 - more verbose)', dest="debug", default=0)
    return parser.parse_args()


def connect_to_host(list_commands, list_devices, flag_cisco=False):
    return_message = ""
    try:
        id_ssh = nm.ConnectHandler(**list_devices)
        id_ssh.read_channel()
        find_hostname = id_ssh.find_prompt()
        if not find_hostname:
            time.sleep(0.1)
            find_hostname = id_ssh.find_prompt()
        hostname = re.match("root@([^:]*):~#", find_hostname).group(1).strip()
        logger.info(f"Connected to hostname: {hostname} with Ip : {list_devices['ip']} ... OK")
        for cmd in list_commands:
            cmd_return = id_ssh.send_command(cmd)
            logger.info(f'Run command: {cmd} ... OK')
            return_message += '{}\n'.format(cmd_return)
        return return_message
    except Exception as error:
        logger.error(f'{error} Exit script ...')
        # logger.error("Exit script ...")
        exit(1)
    return return_message


def get_console_handler():
    console_handler = logging.StreamHandler(sys.stdout)
    console_formater = logging.Formatter('%(funcName)-20s - %(levelname)-8s - %(message)s')
    console_handler.setFormatter(console_formater)
    return console_handler


def get_file_handler(logging_file):
    file_handler = logging.FileHandler(logging_file, mode='w')
    console_formater = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(console_formater)
    return file_handler


def get_logger(logger_name, level_name, logging_file):
    logger = logging.getLogger(logger_name)
    logger.setLevel(level_name)
    logger.addHandler(get_console_handler())
    logger.addHandler(get_file_handler(logging_file))
    logger.propagate = False
    return logger


def get_unl_file(find_unl_file, dict_netmiko):
    local_unl_file = 'eve-ng.unl'
    logger.info("Get UNL file ...")
    # Find path of UNL file on EVE-NG
    ret_msg = connect_to_host([f'find /opt/unetlab/ -iname {find_unl_file}'], dict_netmiko)
    path_to_config = ret_msg.split("\n")[0].strip()
    logger.info(f"Finded unl file: {path_to_config}")
    # Get UNL file
    id_conn_paramiko = paramiko.SSHClient()
    id_conn_paramiko.set_missing_host_key_policy(paramiko.WarningPolicy)
    id_conn_paramiko.connect(dict_netmiko['ip'], username=dict_netmiko['username'], password=dict_netmiko['password'])
    with scp.SCPClient(id_conn_paramiko.get_transport()) as id_scp:
        id_scp.get(path_to_config, local_unl_file)
    logger.info(f'Get file {path_to_config} ... OK')

    unl_list_uuid = list()
    unl_param = dict()
    # Analyze UNL file
    with open(local_unl_file, mode='r') as id_unl:
        content_xml = id_unl.read()
    dict_xml = xmltodict.parse(content_xml)
    for rec_desc_router in dict_xml['lab']['topology']['nodes']['node']:
        logger.debug(f'RECORD_XML: {rec_desc_router}')
        if "@uuid" in rec_desc_router:
            logger.debug('Name:{@name}  UUID: {@uuid}'.format_map(rec_desc_router))
            # unl_param[rec_desc_router['@name']] = rec_desc_router['@uuid']
            unl_param[rec_desc_router['@uuid']] = rec_desc_router['@template']
            # logger.info(f'unl_param: {unl_param}')
            # unl_list_uuid.append(rec_desc_router['@uuid'])
            unl_list_uuid.append(unl_param)
    # logger.info(f'UNL: {unl_list_uuid}')
    # return unl_list_uuid
    return unl_param


def get_processes_unl_param(dict_netmiko, unl_check_uuid):
    ret_msg = connect_to_host(['ps -ax | grep qemu_wrapper'], dict_netmiko)
    ret_param_proc = dict()
    for ss in ret_msg.split("\n"):
        proc_variable = dict()
        logger.debug(ss)
        if re.search("uuid", ss):
            re_res = re.match(r'[^-]*-C\s(\d*)\s-T\s\d*\s-D\s\d*\s-t\s([^-]*).*-uuid\s*([^q]*).*', ss)
            proc_variable['uuid'] = re_res.group(3).strip('-').strip()
            proc_variable['host_name'] = re_res.group(2).strip().lower()
            proc_variable['port'] = re_res.group(1)
            logger.debug(proc_variable['uuid'])
            if proc_variable['uuid'].strip() in unl_check_uuid:
                proc_variable['template'] = unl_check_uuid[proc_variable['uuid'].strip()]
                ret_param_proc[proc_variable['host_name'].strip().lower()] = proc_variable
                logger.debug('uuid:{uuid} host:{host_name} telnet_port:{port}'.format_map(proc_variable))
    return ret_param_proc


def load_config(file_config):
    # file_config = "eveng.cfg"
    logger.info(f'File with configuration: {file_config}')
    with open(file_config, mode='r') as id_cfg:
        cfg_strings = id_cfg.read()
    logger.debug(f'File content: {cfg_strings}')
    cfg_router_dict = dict()
    for ss in cfg_strings.split("\n"):
        if (ss.strip()) and (ss.find('!')):
            logger.debug(f'Cfg string: {ss}')
            ss_list = ss.split(';')
            logger.debug(ss_list)
            r_cfg = dict()
            ip_net = IPNetwork(ss_list[2])
            r_cfg['int'] = ss_list[1]
            r_cfg['ip'] = str(ip_net.ip)
            r_cfg['mask'] = str(ip_net.netmask)
            r_cfg['prefix'] = str(ip_net.prefixlen)
            r_cfg['route'] = ss_list[3]
            cfg_router_dict[ss_list[0]] = r_cfg
    return cfg_router_dict


def configure_csr1000v(rt, pr_param, rt_cfg, dict_netmiko):
    cmd_list = [
        "terminal length 0",
        "conf t",
        "no service config",
        f"default int {rt_cfg[rt]['int']}",
        f"int {rt_cfg[rt]['int']}",
        f"ip add {rt_cfg[rt]['ip']} {rt_cfg[rt]['mask']}",
        "no shut",
        f"ip route 0.0.0.0 0.0.0.0 {rt_cfg[rt]['route']}",
        f"hostname {rt.upper()}",
        "ip domain-name incoma.ru",
        "crypto key generate rsa modulus 2048",
        "aaa new-model",
        "aaa authentication login default local",
        "aaa authorization exec default local ",
        "enable password cisco",
        "username root privilege 15 password cisco",
        "end",
    ]
    logger.info(f"========== Name: {rt.upper()}  Port: {pr_param[rt]['port']} ============")
    logger.debug(cmd_list)
    cmd_telnet = f"telnet {dict_netmiko['ip']}  {pr_param[rt]['port']}"
    logger.info(f"Run telnet: {cmd_telnet} ")
    ch = pexpect.spawn(cmd_telnet, encoding='utf-8')
    ch.delaybeforesend = None
    time.sleep(5)
    logger.info(f"Conf: {rt_cfg[rt]['int']} {rt_cfg[rt]['ip']} {rt_cfg[rt]['mask']} {rt_cfg[rt]['route']} ")
    ch.sendline("\n\n\n")
    ch.sendline("enable\n")
    ch.expect("#")
    for cmd in cmd_list:
        ch.sendline(f"{cmd}")
        ch.expect("#")
    logger.info(f"Run commands ... OK")
    ch.close()


def configure_xrv(rt, pr_param, rt_cfg, dict_netmiko):
    cmd_list = [
        "configure",
        f"hostname {rt.upper()}",
        f"int {rt_cfg[rt]['int']}",
        f"ipv4 add {rt_cfg[rt]['ip']}/{rt_cfg[rt]['prefix']}",
        "no shut",
        "exit",
        "router static",
        f"address-family ipv4 unicast 0.0.0.0/0 {rt_cfg[rt]['route']}",
        "exit",
        "domain name incoma.ru",
        "ssh server v2"
        # "commit"
        # "exit",
        # "crypto key generate rsa\n"
    ]
    logger.info(f"========== Name: {rt.upper()}  Port: {pr_param[rt]['port']} ============")
    logger.info(cmd_list)
    cmd_telnet = f"telnet {dict_netmiko['ip']}  {pr_param[rt]['port']}"
    logger.info(f"Run telnet: {cmd_telnet} ")
    ch = pexpect.spawn(cmd_telnet, encoding='utf-8')
    ch.delaybeforesend = None
    time.sleep(5)
    logger.info(f"Conf: {rt_cfg[rt]['int']} {rt_cfg[rt]['ip']} {rt_cfg[rt]['prefix']} {rt_cfg[rt]['route']} ")
    ch.sendline("\n")
    ch.expect("username:")
    ch.sendline("alex")
    logger.info(f"send alex")

    ch.expect("secret:")
    ch.sendline("cisco")
    logger.info(f"send cisco")

    ch.expect("again:")
    ch.sendline("cisco")
    logger.info(f"send cisco")
#    time.sleep(5)
#    ch.sendline("\n")
    ch.expect("Username:")
    ch.sendline("alex")
    ch.sendline("cisco")
    logger.info(f"Expect command line")
    ch.expect("#")
    for cmd in cmd_list:
        ch.sendline(f"{cmd}\n")
        ch.expect("#")
    ch.sendline("commit")
    time.sleep(5)
    ch.sendline("\n")
    ch.expect("#")
    ch.sendline("exit")
    ch.expect("#")
    ch.sendline("crypto key generate rsa\n")
    ch.expect("#")
    logger.info(f"Run commands ... OK")
    ch.close()


def configure_router(pr_param, rt_cfg, dict_netmiko):
    logger.info(f"========== Configure Routers ===========")
    for rt in sorted(pr_param):
        logger.info(f"rt: {rt}")
        if pr_param[rt]['template'] in template_list and rt in rt_cfg:
            if pr_param[rt]['template'] == 'csr1000vng':
                configure_csr1000v(rt, pr_param, rt_cfg, dict_netmiko)
            if pr_param[rt]['template'] == 'xrv':
                configure_xrv(rt, pr_param, rt_cfg, dict_netmiko)


def main():
    username_ssh = "root"
    password_ssh = "cisco"
    # =======================================================================
    # Get arguments command line
    # =======================================================================
    desc_prog = "EVE-NG: Configure routers in EVE-NG, v1.0"
    epilog_prog = "Alexey: alexeykr@gmail.ru"
    arg = check_argument_parser(desc_prog, epilog_prog)
    if arg.unl_file:
        logger.info(f'UNL File: {arg.unl_file}')
        find_unl_file = arg.unl_file
    else:
        logger.error("Need name of UNL file")
        exit(1)
    if arg.host_ip:
        logger.info(f'EVE-NG ip: {arg.host_ip}')
        ip_host_ssh = arg.host_ip
    else:
        logger.info(f'Need ip EVE-NG ')
        exit(1)
    if arg.conf_file:
        conf_file = arg.conf_file
    else:
        conf_file = "eveng.cfg"

    logger.info("Run script...")
    dict_netmiko = dict()
    dict_netmiko['ip'] = ip_host_ssh
    dict_netmiko['device_type'] = "linux"
    dict_netmiko['password'] = password_ssh
    dict_netmiko['username'] = username_ssh
    logger.info("Get unl file from EVE ...")
    # Get unl File and parse parameters of router
    unl_param = get_unl_file(find_unl_file, dict_netmiko)
    logger.debug(f'UNL_PARAM: {unl_param}')
    proc_param = get_processes_unl_param(dict_netmiko, unl_param)
    logger.debug(f'PROC_PARAM: {proc_param}')
    cfg_routers_dict = load_config(conf_file)
    logger.debug(cfg_routers_dict)
    configure_router(proc_param, cfg_routers_dict, dict_netmiko)


if __name__ == '__main__':
    logging_file = "eveng-configure.log"
    template_list = ['csr1000vng', 'xrv']
    logger = get_logger(__name__, logging.INFO, logging_file)
    # logging.basicConfig(level=logging.DEBUG)
    main()
