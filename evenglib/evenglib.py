#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Configure S-Terra
#
# alexeykr@gmail.com
# coding=utf-8
# import codecs
"""
Classes for change configuration of router on EVE-NG
version: 1.0
@author: alexeykr@gmail.com
"""
import paramiko
import scp
import re
import time
import netmiko as nm
import warnings
import logging
import sys
import pexpect
import xmltodict
from netaddr import IPNetwork
warnings.filterwarnings(action='ignore', module='.*paramiko.*')

# Class EVENGLIB for


class MyLogging:
    """ For logging configuration """

    def __init__(self, level, log_name):
        self.__logging_level = level
        self.__logging_name = log_name

    def get_logger(self):
        logger = logging.getLogger(self.__logging_name)
        logger.setLevel(self.__logging_level)
        console_handler = logging.StreamHandler(sys.stdout)
        console_formater = logging.Formatter('%(name)-10s: %(funcName)-20s - %(levelname)-8s - %(message)s')
        console_handler.setFormatter(console_formater)
        logger.addHandler(console_handler)
        logger.propagate = False
        return logger


class EveUnl:
    """ Class for save parameters of nodes """

    def __init__(self, nod_id='', nod_name='', nod_uuid='', nod_type='', nod_template='', nod_firstmac=''):
        self.__nod_uuid = nod_uuid
        self.__nod_id = nod_id
        self.__nod_type = nod_type
        self.__nod_name = nod_name
        self.__nod_template = nod_template
        self.__nod_firstmac = nod_firstmac
        self.__nod_port = ''
        self.__nod_mgm_int = ''
        self.__nod_mgm_ip = ''
        self.__nod_mgm_mask = ''
        self.__nod_mgm_prefix = ''
        self.__nod_mgm_gw = ''

    @property
    def name(self):
        return self.__nod_name

    @property
    def uuid(self):
        return self.__nod_uuid

    @property
    def id(self):
        return self.__nod_id

    @property
    def type(self):
        return self.__nod_type

    @property
    def template(self):
        return self.__nod_template

    @property
    def firstmac(self):
        return self.__nod_firstmac

    @property
    def port(self):
        return self.__nod_port

    @port.setter
    def port(self, new_port):
        self.__nod_port = new_port

    @property
    def mgm_prefix(self):
        return self.__nod_mgm_prefix

    @property
    def mgm_ip(self):
        return self.__nod_mgm_ip

    @property
    def mgm_mask(self):
        return self.__nod_mgm_mask

    @property
    def mgm_int(self):
        return self.__nod_mgm_int

    @property
    def mgm_gw(self):
        return self.__nod_mgm_gw

    def configure_network(self, mgm_int, mgm_ip, mgm_mask, mgm_prefix, mgm_gw):
        self.__nod_mgm_int = mgm_int
        self.__nod_mgm_ip = mgm_ip
        self.__nod_mgm_mask = mgm_mask
        self.__nod_mgm_prefix = mgm_prefix
        self.__nod_mgm_gw = mgm_gw

    def __str__(self):
        return f'Name={self.__nod_name} Port={self.__nod_port} Template={self.__nod_template} UUID={self.__nod_uuid} MGMT={self.__nod_mgm_int} MGMIP={self.__nod_mgm_ip}/{self.__nod_mgm_prefix}'


# Class EVENGLIB for


class EveNgLab:
    """ Collect some information about lab from unl file and processes in EVE-NG """

    def __init__(self, unl_file, eve_ip_host='', eve_ssh_username='root', eve_ssh_password='cisco', template_list=['csr1000vng', 'xrv'], file_config='eveng.cfg'):
        self.__template_list = template_list
        self.__unl_file = unl_file
        self.__file_config = file_config
        self.__eveng_conn_param = dict()
        self.__eveng_conn_param['ip'] = eve_ip_host
        self.__eveng_conn_param['device_type'] = "linux"
        self.__eveng_conn_param['password'] = eve_ssh_password
        self.__eveng_conn_param['username'] = eve_ssh_username
        self.__local_unl_file = "eve-ng.unl"
        self.__find_unl_file = f'find /opt/unetlab/ -iname "*{self.__unl_file}*.unl"'
        self.__lab_param = dict()
        self.__lg = MyLogging(logging.INFO, "EveNgLab")
        self.__logger = self.__lg.get_logger()

    def __str__(self):
        return f'Device type : {self.__template_list}'

    def eveng_conn_param(self, eve_ip_host, eve_ssh_username, eve_ssh_password):
        self.__eveng_conn_param['ip'] = eve_ip_host
        self.__eveng_conn_param['password'] = eve_ssh_password
        self.__eveng_conn_param['username'] = eve_ssh_username

    def __connect_to_host(self, cmd_run):
        return_message = ""
        # print(f'Connect to host: {self.__eveng_conn_param}')
        try:
            id_ssh = nm.ConnectHandler(**self.__eveng_conn_param)
            id_ssh.read_channel()
            find_hostname = id_ssh.find_prompt()
            if not find_hostname:
                time.sleep(0.1)
                find_hostname = id_ssh.find_prompt()
            hostname = re.match("root@([^:]*):~#", find_hostname).group(1).strip()
            self.__logger.info(f"Connected to hostname: {hostname} with Ip : {self.__eveng_conn_param['ip']} ... OK")
            cmd_return = id_ssh.send_command(cmd_run)
            self.__logger.debug(f'Run command: {cmd_run} ... OK')
            return_message += '{}\n'.format(cmd_return)
            return return_message
        except Exception as error:
            self.__logger.error(f'{error} Exit script ...')
            # logger.error("Exit script ...")
            exit(1)
        return return_message

    def get_proc_param(self):
        ret_msg = self.__connect_to_host('ps -ax | grep qemu_wrapper')
        for ss in ret_msg.split("\n"):
            proc_variable = dict()
            self.__logger.debug(ss)
            if re.search("uuid", ss):
                re_res = re.match(r'[^-]*-C\s(\d*)\s-T\s\d*\s-D\s\d*\s-t\s([^-]*).*-uuid\s*([^q]*).*', ss)
                proc_variable['uuid'] = re_res.group(3).strip('-').strip()
                proc_variable['host_name'] = re_res.group(2).strip().lower()
                proc_variable['port'] = re_res.group(1)
                if proc_variable['host_name'] in self.__lab_param:
                    self.__logger.debug('uuid:{uuid} host:{host_name} telnet_port:{port}'.format_map(proc_variable))
                    self.__lab_param[proc_variable["host_name"]].port = proc_variable['port']
        return self.__lab_param

    def get_unl_file(self):
        # local_unl_file = 'eve-ng.unl'
        self.__logger.info(f'Find UNL file on EVE-NG : {self.__find_unl_file}')
        # Find path of UNL file on EVE-NG
        ret_msg = self.__connect_to_host(self.__find_unl_file)
        path_to_unl = ret_msg.split("\n")[0].strip()
        # print(f'Path: {path_to_unl}')
        self.__logger.info(f"Finded unl file: {path_to_unl}")
        # Get UNL file
        id_conn_paramiko = paramiko.SSHClient()
        id_conn_paramiko.set_missing_host_key_policy(paramiko.WarningPolicy)
        id_conn_paramiko.connect(self.__eveng_conn_param['ip'], username=self.__eveng_conn_param['username'], password=self.__eveng_conn_param['password'])
        with scp.SCPClient(id_conn_paramiko.get_transport()) as id_scp:
            id_scp.get(path_to_unl, self.__local_unl_file)
        self.__logger.info(f'Get file {path_to_unl} ... OK')
        # Analyze UNL file
        unl_param = dict()
        with open(self.__local_unl_file, mode='r') as id_unl:
            content_xml = id_unl.read()
        dict_xml = xmltodict.parse(content_xml)
        for router in dict_xml['lab']['topology']['nodes']['node']:
            self.__logger.debug(f'RECORD_XML: {router}')
            if "@uuid" in router:
                self.__logger.debug('Name:{@name}  UUID: {@uuid}'.format_map(router))
                eve = EveUnl(nod_name=router['@name'].lower(), nod_template=router['@template'], nod_id=router['@id'], nod_type=router['@type'], nod_uuid=router['@uuid'])
                unl_param[router['@name'].strip().lower()] = eve
        self.__logger.debug(f'UNL: {unl_param}')
        self.__lab_param = unl_param
        return unl_param

    def load_config(self):
        self.__logger.info(f'File with configuration: {self.__file_config}')
        with open(self.__file_config, mode='r') as id_cfg:
            cfg_strings = id_cfg.read()
        self.__logger.debug(f'File content: {cfg_strings}')
        for ss in cfg_strings.split("\n"):
            if (ss.strip()) and (ss.find('!')):
                self.__logger.debug(f'Cfg string: {ss}')
                ss_list = ss.split(';')
                self.__logger.debug(ss_list)
                ip_net = IPNetwork(ss_list[2])
                if ss_list[0] in self.__lab_param:
                    self.__lab_param[ss_list[0]].configure_network(ss_list[1], str(ip_net.ip), str(ip_net.netmask), str(ip_net.prefixlen), ss_list[3])
        return self.__lab_param

    @property
    def unl_lab_param(self):
        return self.__lab_param

    # @property
    # def lab_param(self):
    #     return self.__template_list

    # @device_type.setter
    # def device_type(self, new_dv):
    #     self.__template_list = new_dv


class EveNgConf:
    """ Configure nodes of EVE-NG using module pexpect """

    def __init__(self, evenglib, eve_ip_host):
        self.__evenglib = evenglib
        self.__eveng_host = eve_ip_host
        self.__lg = MyLogging(logging.INFO, "EveNgConf")
        self.__logger = self.__lg.get_logger()

    def run_conf_eve(self):
        for rt in self.__evenglib:
            if self.__evenglib[rt].mgm_ip:
                self.__logger.info(f'RT: {rt} Port: {self.__evenglib[rt].port} IP: {self.__evenglib[rt].mgm_ip}  Template: {self.__evenglib[rt].template}')
                if self.__evenglib[rt].template.strip() == "csr1000vng":
                    cmd_run = [
                        "\n\nenable",
                        "terminal length 0",
                        "conf t",
                        "no service config",
                        f"default int {self.__evenglib[rt].mgm_int}",
                        f"int {self.__evenglib[rt].mgm_int}",
                        f"ip add {self.__evenglib[rt].mgm_ip} {self.__evenglib[rt].mgm_mask}",
                        "no shut",
                        f"ip route 0.0.0.0 0.0.0.0 {self.__evenglib[rt].mgm_gw}",
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
                elif (self.__evenglib[rt].template.strip() == "xrv"):
                    cmd_run = [
                        "configure",
                        f"hostname {rt.upper()}",
                        f"int {self.__evenglib[rt].mgm_int}",
                        f"ipv4 add {self.__evenglib[rt].mgm_ip}/{self.__evenglib[rt].mgm_prefix}",
                        "no shut",
                        "exit",
                        "router static",
                        f"address-family ipv4 unicast 0.0.0.0/0 {self.__evenglib[rt].mgm_gw}",
                        "exit",
                        "domain name incoma.ru",
                        "ssh server v2",
                        "commit",
                        "end",
                        "crypto key generate rsa\n"
                    ]

                self.pexpect(rt, self.__eveng_host, self.__evenglib[rt].port, cmd_run, rt_type=self.__evenglib[rt].template)

    def pexpect(self, rt_name, rt_host, rt_port, cmd_run, rt_type="ios"):
        self.__logger.info(f"========== Name: {rt_name.upper()}  Port: {rt_port} ============")
        s = "\n"
        self.__logger.debug(f'CMD: {s.join(cmd_run)}')
        cmd_telnet = f"telnet {rt_host}  {rt_port}"
        self.__logger.info(f"Run telnet: {cmd_telnet} ")
        ch = pexpect.spawn(cmd_telnet, encoding='utf-8')
        ch.delaybeforesend = None
        time.sleep(5)
        if rt_type == "xrv":
            ch.sendline("\n")
            ch.expect("username:")
            ch.sendline("user")
            ch.expect("secret:")
            ch.sendline("cisco")
            ch.expect("again:")
            ch.sendline("cisco")
            ch.expect("Username:")
            ch.sendline("cisco")
            ch.sendline("cisco")
            ch.expect("#")

        for cmd in cmd_run:
            ch.sendline(f"{cmd}")
            ch.expect("#")
        self.__logger.info(f"Run commands ... OK")
        ch.close()
