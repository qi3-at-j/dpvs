#!/usr/bin/env python

import os
import sys
import time
import json
import basic_tools

if sys.getdefaultencoding() != 'utf-8':
    reload(sys)
    sys.setdefaultencoding('utf-8')

vpath_ids = [23251,25313,34020,34059,34143,34146,34152,34172,34201,34203,34204,34205,34206,34207,34208,34209,34210,34211,34212,34213,34214,34215,34216,34217,34973,34974,35729,37051,42164,42181,42499,43167,43174,43372,43381,43385,43459,35,41,53,85,87,89,92,106,112,125,133,136,139,160,187,205,219,220,235,257,268,271,289,290,305,320,351,354,385,394,402,429,435,461,488,581,795,1011,1142,1215,1396,2134,2857,3261,3423,3547,3636,3962,4022,4050,4137,4220,4448,5007,5218,5447,6363,7351,7469,8523,9842,11078,11168,11354,12981,16302,17399,19142,20514,21804,22493,22546,22707,23125,23155,23168,23301,23336,23339,23478,23547,23559,23668,23750,23775,23882,23903,23906,23912,24159,24161,24166,24169,24172,24183,24195,24196,24203,24208,24217,24221,24225,24229,24283,24305,24317,24329,24330,24439,24523,24676,24677,24997,25137,25228,25310,25354,25439,25603,25606,26129,27279,29444,32375,32677,32678,32679,32680,32701,32702,32703,32704,32842,33189,33555,33561,33564,33680,33767,34301,34609,35281,35282,35562,35565,36270,37026,37085,37089,37120,37905,38055,42014,42079,42126,42381,42438,42449,42472,42488,42494,42848,42967,43428,43442,43662,43706,1,2,1833,3376,12071,14031,14763,15140,15947,18197,24343,24344,24349,24653,25105,33591,36910,24321,10425,23079,23147,23928,24184,24287,24357,24515,25593,25597,25616,31137,31503,212,297,2437,3538,4131,5170,7520,9122,9226,9910,9952,10115,10506,10523,11181,11469,11524,11657,12294,13007,13209,13412,14271,16490,16861,16981,21267,21651,23057,23135,23207,23590,24699,24700,24932,24933,24934,25016,25080,25161,25164,25166,25167,25212,30811,30878,31011,31033,31076,31537,32192,33551,33744,36909,37228,37,98,171,188,243,272,302,306,331,332,421,445,448,1170,4801,5422,5649,5752,7202,10887,11017,13972,14607,15074,21294,23061,23360,23473,23527,23543,23577,23803,24243,24276,24508,24727,25017,25018,25025,25210,25443,25458,25901,31416,32066,32354,32374,32380,32532,32681,32880,33045,33082,33177,33239,33416,33827,33958,33983,34038,34202,34280,34326,34334,34346,34588,34961,35170,35192,35203,35544,35598,36534,36636,36642,37070,37074,37142,37515,37903,38458,42095,42177,42215,42426,42439,42450,42508,42544,42628,42633,42935,43023,43079,43097,43150,43248,43249,43251,43427,44219,3842,9282,9516,10303,12489,14342,14767,17014,21565,24648,34225,34271,34592,35535,35597,35833,36405,37339,41468,42355,42414,42715,213,11162,15517,24242,24323,25605,33617,33823,35784,42396,316,443,21633,10918,25278,33727,33794,24829,25594,4642,23084,24311,24806,33665,481,23901,30464,33569,25602,25604,33835,16,1592,164,248,288,6267,36680,31692,4064,13498,24247,34353,34579,34862,42363,3903,6999,8893,14666,33592,33603,36646,237,367,23907,33575,34270,34276,34321,34673,35594,38300,38313,25587,17053,23115,24490,24826,24828,25224,25230,25279,25280,43219,43222,43250,751,1599,2011,4464,24821,299,24215,24892,33601,337,5359,6142,7223,10753,19800,24625,24680,24683,24688,24831,25133,25249,33933,32115]

proto_not_support = 0

method_info_dict = dict()

def write_tail_info_proc(suci_rule_f,tail_part_rule):
    for each_opt in tail_part_rule:
        suci_rule_f.write(each_opt)

def gen_suri_rule_file(detect_dict,suci_rule_f,proto_id_name_dict):
    for each_r in detect_dict:
        pre_rule_info = ''
        h_method = ''
        last_rule_info = ''
        sig_type = detect_dict[each_r]['sig_type']
        if sig_type == 2:
            continue
        sid = each_r
        rev = detect_dict[each_r]['ver']
        if rev == 0:
            rev = 1
        sess_dir = detect_dict[each_r]['sess_dir'] if detect_dict[each_r].has_key('sess_dir') else None
        sess_state = detect_dict[each_r]['sess_state'] if detect_dict[each_r].has_key('sess_state') else None
        action = detect_dict[each_r]['action']

        # 10-low  30-middle  60-high  90-serious
        severity = detect_dict[each_r].get('level', 10)

        r_type = ''
        if each_r in method_info_dict:
            r_type = method_info_dict[each_r].get('method', 'Other')
        else:
            r_type = 'Other'
            print('rule {} not exist in method dict'.format(each_r))

        prot_int = detect_dict[each_r]['l5appid'] if detect_dict[each_r].has_key('l5appid') else detect_dict[each_r]['l4pro']
        if not basic_tools.proto_id_release.has_key(prot_int):
            global proto_not_support
            proto_not_support += 1
            continue

        msg = detect_dict[each_r]['descript'] if detect_dict[each_r].has_key('descript') else None
        src_ip = 'any'
        dest_ip = 'any'
        dest_port = detect_dict[each_r]['dest_port'] if detect_dict[each_r].has_key('dest_port') else 'any'
        src_port = detect_dict[each_r]['src_port'] if detect_dict[each_r].has_key('src_port') else 'any'
        http_method = detect_dict[each_r]['http_method'] if detect_dict[each_r].has_key('http_method') else None
        #pre_rule_info,h_method = basic_tools.gen_pre_part_rule(action,prot_int,src_port,dest_port,msg,sess_dir, sess_state,http_method,proto_id_name_dict)

        sig_info = detect_dict[each_r]['sig'] if detect_dict[each_r].has_key('sig') else None
        if sig_info == None:
            # only_rule_opt_do_not_used now.
            continue
        sig_cnt = 0

        gid = ''
        if sid in vpath_ids:
            gid = '4'

        for each_sig in sig_info:
            aera_content = ''
            mult_rid = (sig_cnt << 16) + sid
            sig_cnt += 1
            inner_part_rule = ''
            tail_part_rule = ''

            # tmp TODO
            if mult_rid == 42562:
                continue

            # tmp distance depth conflict
            #if mult_rid == 43580 or mult_rid == 43584 or mult_rid == 43653:
            #    continue

            # conflict for direction http.uri
            dir_conflict_with_uri = [43872, 73638, 32844, 24980, 97044, 33306, 36532, 37562, 103819, 42385, 43076, 43646, 43677]
            if mult_rid in dir_conflict_with_uri and sess_dir == 1:
                sess_dir = 0

            # conflict for direction http.server http.location
            conflict_expected1_with_0_dir = [37047, 102583, 38283]
            if mult_rid in conflict_expected1_with_0_dir and sess_dir == 0:
                sess_dir = 1

            # conflict for none direction
            conflict_none_dir = [42555, 42556, 42567, 42558]
            if mult_rid in conflict_none_dir and sess_dir == None:
                sess_dir = 0

            # conflict for without a flow direction
            conflict_expected0_with_both_dir = [42661, 42703, 42819, 27545]
            if mult_rid in conflict_expected0_with_both_dir and sess_dir == 2:
                sess_dir = 0

            # conflict for without a flow direction
            conflict_expected1_with_both_dir = [43473]
            if mult_rid in conflict_expected1_with_both_dir and sess_dir == 2:
                sess_dir = 1

            if sess_dir == 2:
                ac_info = each_sig['ac'] if each_sig.has_key('ac') else None
                if ac_info:
                    inner_part_rule,aera_content,sess_dir_r = basic_tools.gen_inner_part_rule(ac_info,sess_dir,prot_int, mult_rid)
                    if sess_dir_r != sess_dir:
                        sess_dir = sess_dir_r
                        pass

                    if inner_part_rule == '':
                        continue
                else:
                    continue

                opt_info = each_sig['option'] if each_sig.has_key('option') else None
                if opt_info:
                    tail_part_rule,sess_dir_r = basic_tools.gen_tail_part_rule(opt_info,sess_dir,prot_int, mult_rid, int(each_r))
                    if sess_dir_r != sess_dir:
                        sess_dir = sess_dir_r
                        pass

            ac_info = each_sig['ac'] if each_sig.has_key('ac') else None
            if ac_info:
                inner_part_rule,aera_content,sess_dir_r = basic_tools.gen_inner_part_rule(ac_info,sess_dir,prot_int, mult_rid)
                if sess_dir_r != sess_dir:
                    sess_dir = sess_dir_r
                    pass

                if inner_part_rule == '':
                    continue
            else:
                continue

            opt_info = each_sig['option'] if each_sig.has_key('option') else None
            if opt_info:
                tail_part_rule,sess_dir_r = basic_tools.gen_tail_part_rule(opt_info,sess_dir,prot_int, mult_rid, int(each_r))
                if sess_dir_r != sess_dir:
                    sess_dir = sess_dir_r
                    pass

            pre_rule_info,h_method = basic_tools.gen_pre_part_rule(action,prot_int,src_port,dest_port,msg,sess_dir, sess_state,http_method,proto_id_name_dict)

            suci_rule_f.write(pre_rule_info)
            suci_rule_f.write(inner_part_rule)
            write_tail_info_proc(suci_rule_f, tail_part_rule)
            suci_rule_f.write(h_method)
            last_rule_info = basic_tools.gen_last_part_rule(mult_rid, rev, gid, str(r_type), str(severity))
            suci_rule_f.write(last_rule_info)
            # all_one_rule = pre_rule_info + inner_part_rule + tail_part_rule + last_rule_info + '\r\n'
            suci_rule_f.write('\r\n')

def gen_json_detect_desc_proc(detect_f, desc_f,detect_desc_f,suci_rule_f,proto_id_name_dict):
    detect_info = detect_f.read()
    desc_info = desc_f.read()
    detect_dict_s = json.loads(detect_info)
    detect_dict = eval(detect_dict_s)
    desc_dict = json.loads(desc_info)

    for each in desc_dict:
        each_i = int(each)
        detect_dict[each_i]['action'] = desc_dict[each]['act']
        detect_dict[each_i]['descript'] = desc_dict[each]['des']
        detect_dict[each_i]['level'] = desc_dict[each]['level']

    detect_desc_dict_s = str(detect_dict)
    detect_desc_f.write(detect_desc_dict_s)

    print('dict count {}'.format(len(detect_dict)))

    for i in detect_dict:
        if i not in method_info_dict:
            print('detect {} not in method'.format(i))

    for i in method_info_dict:
        if i not in detect_dict:
            print('method {} not in detect'.format(i))

    gen_suri_rule_file(detect_dict,suci_rule_f,proto_id_name_dict)

    global proto_not_support
    print('proto not support {}'.format(proto_not_support))

def integrate_method_info(method_dict):
    # merge method
    for meth_id in method_dict.keys():
        if method_dict[meth_id]['type'] == 1:
            name = method_dict[meth_id]['name']
            for sub_id in method_dict[meth_id]['sub_category']:
                sub_name = method_dict[sub_id]['name']

                #print('Method:', name+'-'+sub_name)
                for rule_id in method_dict[sub_id]['rule-id']:
                    if rule_id not in method_info_dict:
                        if rule_id == 0:
                            print('skip rule 0, method: {}'.format(name + '-' + sub_name))
                            continue
                        method_info_dict[rule_id] = dict()
                        method_info_dict[rule_id]['method'] = (name + '-' + sub_name)

if __name__ == '__main__':
    if len(sys.argv) != 7:
        print('invalid input arg: json_detect(IN),json_desc_act(IN), ips_method(IN), ips_id_name(IN), json_detect_info_all(OUT), suricata_rules(OUT)')
        sys.exit(0)

    json_detect_file = sys.argv[1]
    json_desc_file = sys.argv[2]
    json_method_file = sys.argv[3]
    proto_id_name_rel = sys.argv[4]
    json_detect_desc_file = sys.argv[5]
    suri_rule_file = sys.argv[6]

    detect_f = open(json_detect_file,'r')
    desc_f = open(json_desc_file, 'r')
    method_f = open(json_method_file, 'r')
    proto_id_name_rel_f = open(proto_id_name_rel, 'rb')
    detect_desc_f = open(json_detect_desc_file,'w+')
    suci_rule_f = open(suri_rule_file,'w+')

    method_info = method_f.read()
    method_dict_s = json.loads(method_info)
    method_dict = eval(method_dict_s)

    # get method info
    integrate_method_info(method_dict)
    print('method len {}'.format(len(method_info_dict)))

    proto_id_name_json = proto_id_name_rel_f.read()
    proto_id_name_dict = json.loads(proto_id_name_json)

    proto_id_name_dict['1'] = 'icmp'
    proto_id_name_dict['6'] = 'tcp'
    proto_id_name_dict['17'] = 'udp'

    gen_json_detect_desc_proc(detect_f, desc_f,detect_desc_f,suci_rule_f,proto_id_name_dict)

    detect_f.close()
    desc_f.close()
    proto_id_name_rel_f.close()
    detect_desc_f.close()
    suci_rule_f.close()
