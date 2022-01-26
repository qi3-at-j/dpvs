#!/usr/bin/env python

import os
import sys
import time
import json

if sys.getdefaultencoding() != 'utf-8':
    reload(sys)
    sys.setdefaultencoding('utf-8')

app_id_dict = dict()
appl5_id_dict = dict()
l4pro_dict = dict()

def extract_proto_proc(detect_dict, suci_rule_f):
    for rule_id in detect_dict:
        proto_id = detect_dict[rule_id].get('app_id')
        if proto_id:
            #k = 'app_id_' + str(proto_id)
            #k = 'l7_' + str(proto_id)
            k = int(proto_id)
            if k in app_id_dict.keys():
                app_id_dict[k].append(rule_id)
            else:
                app_id_dict[k] = list()
                app_id_dict[k].append(rule_id)

        if not proto_id:
            proto_id = detect_dict[rule_id].get('l5appid')
            if proto_id:
                #k = 'l5appid_' + str(proto_id)
                #k = 'l5_' + str(proto_id)
                k = int(proto_id)
                if k in appl5_id_dict.keys():
                    appl5_id_dict[k].append(rule_id)
                else:
                    appl5_id_dict[k] = list()
                    appl5_id_dict[k].append(rule_id)

        if not proto_id:
            proto_id = detect_dict[rule_id].get('l4pro')
            if proto_id:
                #k = 'l4pro_' + str(proto_id)
                #k = 'l4_' + str(proto_id)
                k = int(proto_id)
                if k in l4pro_dict.keys():
                    l4pro_dict[k].append(rule_id)
                else:
                    l4pro_dict[k] = list()
                    l4pro_dict[k].append(rule_id)

        if not proto_id:
            print("proto id not found")
            continue

        # multiple sig
        #
        #sig_cnt = 0
        #for each_sig in sig_info:
        #    mult_rid = (sig_cnt << 16) + rule_id
        #


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('invalid input arg: apr_detect_json(IN), proto_file(OUT).')
        sys.exit(0)

    f1 = open(sys.argv[1],'r')
    detect_info = f1.read()
    detect_dict_s = json.loads(detect_info)
    detect_dict = eval(detect_dict_s)
    f1.close()

    extract_proto_proc(detect_dict, '')

    f2 = open(sys.argv[2],'w')

    data = dict()
    data['l7'] = app_id_dict
    data['l5'] = appl5_id_dict
    data['l4'] = l4pro_dict

    data_json = json.dumps(data)
    f2.write(data_json)
    f2.close()

    l7_n = 0
    l5_n = 0
    l4_n = 0

    for k in app_id_dict:
        l7_n += len(app_id_dict[k])

    for k in appl5_id_dict:
        l5_n += len(appl5_id_dict[k])

    for k in l4pro_dict:
        l4_n += len(l4pro_dict[k])

    print("l7:{} l5:{} l4:{}".format(l7_n, l5_n, l4_n))


