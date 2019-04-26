#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Configure S-Terra
#
# alexeykr@gmail.com
# coding=utf-8
# import codecs
import evenglib.evenglib as evng

if __name__ == '__main__':
    logging_file = "eveng-configure.log"
    ev = evng.EveNgLab(unl_file="ansible", eve_ip_host="10.121.1.21", eve_ssh_username="root", eve_ssh_password="cisco")
    ev.get_unl_file()
    ev.get_proc_param()
    ev.load_config()
    # ret_unl_param = ev.unl_lab_param
    evconf = evng.EveNgConf(ev.unl_lab_param, "10.121.1.21")
    evconf.run_conf_eve()

    # for unl in ret_unl_param:
    #     print(ret_unl_param[unl])
    # lab_param = dict()

    # for kk in range(10):
    #     unl = EveUnl("uno" + str(kk), "due" + str(kk), "tre" + str(kk), "quatro" + str(kk), "cincue" + str(kk))
    #     print(unl.name)
    #     lab_param[unl.name] = unl
    #     # print(unl)

    # for ii in lab_param:
    #     print(ii)
    #     print(lab_param[ii])
    # for tmp in ev.device_type:
    #     print(tmp)
