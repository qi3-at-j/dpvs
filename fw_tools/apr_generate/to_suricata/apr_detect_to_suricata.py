#!/usr/bin/env python

import os
import sys
import time
import json
import basic_tools

if sys.getdefaultencoding() != 'utf-8':
    reload(sys)
    sys.setdefaultencoding('utf-8')

proto_not_support = 0
proto_dict = dict()

sigtype_not_support = 0
sig_dict = dict()

def write_tail_info_proc(suci_rule_f,tail_part_rule):
    for each_opt in tail_part_rule:
        suci_rule_f.write(each_opt)

def gen_suri_rule_file(detect_dict, proto_name_dict, suci_rule_f):
    for each_r in detect_dict:
        pre_rule_info = ''
        h_method = ''
        last_rule_info = ''
        sig_type = detect_dict[each_r]['sig_type']
        if sig_type != 0 and sig_type != 2:
            global sigtype_not_support
            sigtype_not_support += 1

            if sig_type in sig_dict.keys():
                sig_dict[sig_type]['rule_list'].append(each_r)
            else:
                sig_dict[sig_type] = dict()
                sig_dict[sig_type]['rule_list'] = list()
                sig_dict[sig_type]['rule_list'].append(each_r)

            continue

        #if each_r != 13 and each_r != 14 and each_r != 31 and each_r != 83:
        #    continue

        sid = each_r
        ver = detect_dict[each_r]['ver']
        if ver == 0:
            ver = 1

        gid = 2
        for x in detect_dict:
            l7 = detect_dict[x].get('app_id')
            l5 = detect_dict[x].get('l5appid')
            l4 = detect_dict[x].get('l4pro')
            if l7 == each_r or l5 == each_r or l4 == each_r:
                gid = 1
                break
                #if basic_tools.proto_id_release.has_key(each_r):

        sess_dir = detect_dict[each_r].get('sess_dir')
        sess_state = detect_dict[each_r].get('sess_state')

        prot_int = detect_dict[each_r].get('app_id')
        if not prot_int or not basic_tools.proto_id_release.has_key(prot_int):
            prot_int = detect_dict[each_r].get('l5appid')
            if not prot_int or not basic_tools.proto_id_release.has_key(prot_int):
                prot_int = detect_dict[each_r].get('l4pro')

        if not prot_int or not basic_tools.proto_id_release.has_key(prot_int):
            global proto_not_support
            proto_not_support += 1
            
            if prot_int in proto_dict.keys():
                proto_dict[prot_int]['rule_list'].append(each_r)
            else:
                proto_dict[prot_int] = dict()
                proto_dict[prot_int]['proto_name'] = proto_name_dict.get(str(prot_int))
                proto_dict[prot_int]['rule_list'] = list()
                proto_dict[prot_int]['rule_list'].append(each_r)

            continue

        # not need TMP
        msg = ''

        http_method = detect_dict[each_r].get('http_method')

        sig_info = detect_dict[each_r].get('sig') 
        if sig_info == None:
            print('{} no sig info'.format(each_r))
            # only_rule_opt_do_not_used now.
            continue

        sig_cnt = 0
        for each_sig in sig_info:
            aera_content = ''
            mult_rid = (sig_cnt << 16) + sid
            sig_cnt += 1
            inner_part_rule = ''
            tail_part_rule = ''

            if sess_dir == 2:
                ac_info = each_sig.get('ac')
                if ac_info:
                    inner_part_rule, aera_content, sess_dir_r = basic_tools.gen_inner_part_rule(ac_info,sess_dir,prot_int, mult_rid, sig_type)
                    if sess_dir_r != sess_dir:
                        sess_dir = sess_dir_r

                    if inner_part_rule == '':
                        print('{} no ac info'.format(each_r))
                        continue
                else:
                    print('{} no ac info'.format(each_r))
                    continue

                opt_info = each_sig.get('option')
                if opt_info:
                    tail_part_rule, sess_dir_r = basic_tools.gen_tail_part_rule(opt_info,sess_dir, prot_int, mult_rid, int(each_r))
                    if sess_dir_r != sess_dir:
                        sess_dir = sess_dir_r

            ac_info = each_sig.get('ac')
            if ac_info:
                inner_part_rule, aera_content, sess_dir_r = basic_tools.gen_inner_part_rule(ac_info,sess_dir,prot_int, mult_rid, sig_type)
                if sess_dir_r != sess_dir:
                    sess_dir = sess_dir_r

                if inner_part_rule == '':
                    print('{} no ac info'.format(each_r))
                    continue
            else:
                print('{} no ac info'.format(each_r))
                continue

            opt_info = each_sig.get('option')
            if opt_info:
                tail_part_rule, sess_dir_r = basic_tools.gen_tail_part_rule(opt_info,sess_dir, prot_int, mult_rid, int(each_r))
                if sess_dir_r != sess_dir:
                    sess_dir = sess_dir_r

            pre_rule_info,h_method = basic_tools.gen_pre_part_rule(prot_int,msg,sess_dir,sess_state,http_method,proto_name_dict)

            suci_rule_f.write(pre_rule_info)
            suci_rule_f.write(inner_part_rule)
            write_tail_info_proc(suci_rule_f, tail_part_rule)
            suci_rule_f.write(h_method)
            last_rule_info = basic_tools.gen_last_part_rule(mult_rid, gid, ver)
            suci_rule_f.write(last_rule_info)
            suci_rule_f.write('\r\n')

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print('invalid input arg: apr_detect_json(IN),apr_id_name(IN),suri_rule_file(OUT)')
        sys.exit(0)

    f1 = open(sys.argv[1],'r')
    detect_info = f1.read()
    detect_dict_s = json.loads(detect_info)
    detect_dict = eval(detect_dict_s)
    f1.close()

    f2 = open(sys.argv[2], 'r')

    proto_name_json = f2.read()
    proto_name_dict = json.loads(proto_name_json)

    proto_name_dict['1'] = 'icmp'
    proto_name_dict['6'] = 'tcp'
    proto_name_dict['17'] = 'udp'
    f2.close()

    suci_rule_f = open(sys.argv[3],'w+')
    gen_suri_rule_file(detect_dict, proto_name_dict, suci_rule_f)
    suci_rule_f.close()

    #global proto_not_support
    print('proto not support {} -- {}'.format(proto_not_support, proto_dict))
    print('sigtype not support {} -- {}'.format(sigtype_not_support, sig_dict))

