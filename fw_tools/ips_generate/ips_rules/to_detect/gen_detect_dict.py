#!/usr/bin/python
# -*- coding: UTF-8 -*-
import os
import sys
import time
import json

def get_value(str):
    r_len = 0
    for n in str:
        p_len = ord(n)
        r_len = r_len * 256 + p_len
    return r_len



def gen_ruleopt_info_proc(json_detect_info,id_r,tlv_len,tlv_v_s):
    cur_ruleopt_pos = 0
    cur_ruleopt_len = 0

    while True:
        ruleopt_tlv_len = get_value(tlv_v_s[cur_ruleopt_pos + 2:cur_ruleopt_pos + 4])
        cur_ruleopt_len += (ruleopt_tlv_len + 4)
        if cur_ruleopt_len > tlv_len:
            print 'invalid http_method'
            break
        cur_tlv_t = get_value(tlv_v_s[cur_ruleopt_pos:cur_ruleopt_pos + 2])
        #print 'rule-opt type' + str(cur_tlv_t)
        cur_tlv_v = tlv_v_s[cur_ruleopt_pos + 4:cur_ruleopt_pos + 4 + ruleopt_tlv_len]
        if cur_tlv_t == 99:
            json_detect_info[id_r]['sess_dir'] = get_value(cur_tlv_v)
        elif cur_tlv_t == 176:
            json_detect_info[id_r]['l5appid'] = get_value(cur_tlv_v)
        elif cur_tlv_t == 19:
            json_detect_info[id_r]['sess_state'] = get_value(cur_tlv_v)
        elif cur_tlv_t == 106:
            gen_method_proc(json_detect_info, id_r, ruleopt_tlv_len, cur_tlv_v)
        elif cur_tlv_t == 104:
            json_detect_info[id_r]['src_port'] = {}
            gen_port_proc(json_detect_info[id_r]['src_port'], ruleopt_tlv_len, cur_tlv_v)
        elif cur_tlv_t == 105:
            json_detect_info[id_r]['dest_port'] = {}
            gen_port_proc(json_detect_info[id_r]['dest_port'], ruleopt_tlv_len, cur_tlv_v)

        if cur_ruleopt_len == tlv_len:
            break
        cur_ruleopt_pos += (4 + ruleopt_tlv_len)

def gen_method_proc(json_detect_info,id_r,tlv_len,tlv_v_s):
    cur_method_pos = 0
    cur_method_len = 0
    json_detect_info[id_r]['http_method'] = []

    while True:
        method_tlv_len = get_value(tlv_v_s[cur_method_pos+2:cur_method_pos+4])
        cur_method_len += (method_tlv_len+4)
        if cur_method_len > tlv_len:
            print 'invalid http_method'
            break
        method_tlv_t = get_value(tlv_v_s[cur_method_pos:cur_method_pos+2])
        assert(method_tlv_t == 164)
        method_tlv_v = tlv_v_s[cur_method_pos+4:cur_method_pos+4+method_tlv_len]
        json_detect_info[id_r]['http_method'].append(method_tlv_v)

        if cur_method_len == tlv_len:
            break
        cur_method_pos += (4+method_tlv_len)

def gen_port_proc(json_port,tlv_len,tlv_v_s):
    cur_port_pos = 0
    cur_port_len = 0


    port_tlv_len = get_value(tlv_v_s[cur_port_pos+2:cur_port_pos+4])
    cur_port_len += (port_tlv_len+4)
    # print cur_port_len
    # print tlv_len
    assert (cur_port_len == tlv_len)

    port_tlv_t = get_value(tlv_v_s[cur_port_pos:cur_port_pos+2])
    assert (port_tlv_t == 134 or port_tlv_t == 135)
    port_tlv_v = tlv_v_s[cur_port_pos+4:cur_port_pos+4+port_tlv_len]
    if port_tlv_t == 134:
        assert (port_tlv_len == 4)
        s_port_s = port_tlv_v[:2]
        e_port_s = port_tlv_v[2:]
        s_port = get_value(s_port_s)
        e_port = get_value(e_port_s)
        json_port['range']=[]
        json_port['range'].append(s_port)
        json_port['range'].append(e_port)

    if port_tlv_t == 135:
        port_list = []
        vlist = port_tlv_v
        port_vlist = [vlist[i:i + 2] for i in range(0, len(vlist), 2)]
        # print port_vlist
        for p in port_vlist:
            pint = get_value(p)
            port_list.append(pint)
        json_port['group'] = port_list

def sig_ac_proc(sig_ac_info,sig_tlv_len,sig_ac_v):
    cur_ac_pos = 0
    cur_ac_len = 0
    sig_ac_info['pattern'] = []

    while True:
        ac_tlv_len = get_value(sig_ac_v[cur_ac_pos+2:cur_ac_pos+4])
        cur_ac_len += (ac_tlv_len+4)

        if cur_ac_len > sig_tlv_len:
            print 'invalid ac proc'
            break

        ac_tlv_t = get_value(sig_ac_v[cur_ac_pos:cur_ac_pos+2])
        ac_tlv_v = sig_ac_v[cur_ac_pos+4:cur_ac_pos+4+ac_tlv_len]
        if ac_tlv_t == 164:
            sig_ac_info['pattern'].append(ac_tlv_v)
        elif ac_tlv_t == 165:
            sig_ac_info['position'] = get_value(ac_tlv_v)
        elif ac_tlv_t == 166:
            sig_ac_info['head_name'] = ac_tlv_v
        elif ac_tlv_t == 167:
            sig_ac_info['nocase'] = get_value(ac_tlv_v)
        elif ac_tlv_t == 168:
            sig_ac_info['offset'] = get_value(ac_tlv_v)
        elif ac_tlv_t == 170:
            sig_ac_info['depth'] = get_value(ac_tlv_v)
        elif ac_tlv_t == 172:
            sig_ac_info['distance'] = get_value(ac_tlv_v)
        elif ac_tlv_t == 174:
            sig_ac_info['within'] = get_value(ac_tlv_v)
        else:
            pass

        if cur_ac_len == sig_tlv_len:
            break

        cur_ac_pos += (4+ac_tlv_len)

def sig_option_proc(sig_opt_info,sig_tlv_t,sig_tlv_len,sig_opt_v):
    cur_opt_pos = 0
    cur_opt_len = 0
    sig_opt_info['pattern'] = []
    sig_opt_info['type'] = 'content' if sig_tlv_t == 260 else 'regex'

    while True:
        opt_tlv_len = get_value(sig_opt_v[cur_opt_pos + 2:cur_opt_pos + 4])
        cur_opt_len += (opt_tlv_len + 4)

        if cur_opt_len > sig_tlv_len:
            print
            'invalid opt proc'
            break

        opt_tlv_t = get_value(sig_opt_v[cur_opt_pos:cur_opt_pos + 2])
        opt_tlv_v = sig_opt_v[cur_opt_pos + 4:cur_opt_pos + 4 + opt_tlv_len]

        if opt_tlv_t == 164 or opt_tlv_t == 16:
            sig_opt_info['pattern'].append(opt_tlv_v)
        elif opt_tlv_t == 165:
            sig_opt_info['position'] = get_value(opt_tlv_v)
        elif opt_tlv_t == 166:
            sig_opt_info['head_name'] = opt_tlv_v
        elif opt_tlv_t == 167:
            sig_opt_info['nocase'] = get_value(opt_tlv_v)
        elif opt_tlv_t == 168:
            sig_opt_info['offset'] = get_value(opt_tlv_v)
        elif opt_tlv_t == 170:
            sig_opt_info['depth'] = get_value(opt_tlv_v)
        elif opt_tlv_t == 172:
            sig_opt_info['distance'] = get_value(opt_tlv_v)
        elif opt_tlv_t == 174:
            sig_opt_info['within'] = get_value(opt_tlv_v)
        elif opt_tlv_t == 160:
            sig_opt_info['negative'] = get_value(opt_tlv_v)
        else:
            pass

        if cur_opt_len == sig_tlv_len:
            break

        cur_opt_pos += (4 + opt_tlv_len)

def gen_sig_info_proc(json_detect_sig_list,tlv_t,tlv_len,tlv_v_s):
    sig_value = {}
    sig_cur_pos = 0
    sig_cur_len = 0

    while True:
        sig_tlv_len = get_value(tlv_v_s[sig_cur_pos+2:sig_cur_pos+4])
        sig_cur_len += (sig_tlv_len+4)
        if sig_cur_len > tlv_len:
            print 'invalid sig'
            break
        sig_tlv_t = get_value(tlv_v_s[sig_cur_pos:sig_cur_pos+2])
        if sig_tlv_t == 263 or sig_tlv_t == 262:
            sig_value['ac'] = {}
            # print 'sig_tlv_ac:' + str(sig_tlv_len)
            sig_ac_v = tlv_v_s[sig_cur_pos+4:sig_cur_pos+4+sig_tlv_len]
            sig_ac_proc(sig_value['ac'],sig_tlv_len,sig_ac_v)

        elif sig_tlv_t == 259 or sig_tlv_t == 260:
            if not sig_value.has_key('option'):
                sig_value['option'] = {}
                option_cnt = 0
            else:
                option_cnt = len(sig_value['option'])
            sig_value['option'][option_cnt] = {}
            sig_opt_v = tlv_v_s[sig_cur_pos + 4:sig_cur_pos + 4 + sig_tlv_len]
            sig_option_proc(sig_value['option'][option_cnt],sig_tlv_t,sig_tlv_len,sig_opt_v)

        if sig_cur_len == tlv_len:
            break
        sig_cur_pos += (4+sig_tlv_len)
    json_detect_sig_list.append(sig_value)
    # print 'after sig proc:' + str(json_detect_sig_list)

def gen_tlv_info_proc(tlv_t,tlv_len,tlv_v_s,json_detect_info,id_r):
    if tlv_t == 14:
        json_detect_info[id_r]['l4pro'] = get_value(tlv_v_s)
    elif tlv_t == 96:
        json_detect_info[id_r]['sig_type'] = get_value(tlv_v_s)
    elif tlv_t == 256:
        gen_ruleopt_info_proc(json_detect_info,id_r,tlv_len,tlv_v_s)
    elif tlv_t == 257 or tlv_t == 258:
        # print 'before proc sig, json info:' + str(json_detect_info)
        # print 'sig info' + str(tlv_len)
        if not json_detect_info[id_r].has_key('sig'):
            json_detect_info[id_r]['sig'] = []
        gen_sig_info_proc(json_detect_info[id_r]['sig'],tlv_t,tlv_len,tlv_v_s)

def gen_json_detect_body_proc(json_detect_info,body_r_s,body_r_len,id_r):
    cur_r_len = 0
    cur_pos = 0
    if body_r_len == 0:
        return
    while True:
        tlv_len_s = body_r_s[cur_pos+2:cur_pos+4]
        tlv_len = get_value(tlv_len_s)
        cur_r_len += (tlv_len + 4)
        if cur_r_len > body_r_len:
            print 'invalid rule info'
            break
        tlv_t = get_value(body_r_s[cur_pos:cur_pos+2])
        # print 'type:' + str(tlv_t)
        tlv_v_s = body_r_s[cur_pos+4:cur_pos+4+tlv_len]
        gen_tlv_info_proc(tlv_t,tlv_len,tlv_v_s,json_detect_info,id_r)
        if cur_r_len == body_r_len:
            break
        cur_pos += (tlv_len + 4)

def gen_json_detect_proc(detect_f, json_detect_info):
    detect_f.seek(0,2)
    detect_len = detect_f.tell()
    print 'detect_body file length is ' + str(detect_len)
    detect_f.seek(0,0)
    rule_cnt = 0

    body_r_len = 0
    cur_body_len = 0
    while True:
        detect_f.seek(8,1)
        body_r_len_s = detect_f.read(2)
        body_r_len = get_value(body_r_len_s)
        r_len = body_r_len + 12
        cur_body_len += r_len

        if cur_body_len > detect_len:
            print 'invalid rule info cross'
            break

        detect_f.seek(-10,1)
        id_r_s = detect_f.read(4)
        id_r = get_value(id_r_s)
        ver_r_s = detect_f.read(2)
        ver_r = get_value(ver_r_s)
        # print 'rule id :' + str(id_r)
        rule_cnt += 1
        json_detect_info[id_r] = {}
        json_detect_info[id_r]['ver'] = ver_r
        detect_f.seek(6,1)
        body_r_s = detect_f.read(body_r_len)
        gen_json_detect_body_proc(json_detect_info,body_r_s,body_r_len,id_r)
        if cur_body_len == detect_len:
            break
    print 'all rule cnt is :' + str(rule_cnt)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print 'invalid input arg: body_detect(IN), json_detect_dict(OUT)'
        sys.exit(0)
    detect_file = sys.argv[1]
    json_detect_file = sys.argv[2]
    detect_f = open(detect_file,'r')
    json_detect_info = {}
    gen_json_detect_proc(detect_f, json_detect_info)
    # json_detect_info_s = json.dumps(json_detect_info)
    # print 'after all proc:' + str(json_detect_info)
    detect_f.close()
    
    json_detect_f = open(json_detect_file, 'w+')
    s_json_detect_info = str(json_detect_info)
    json_detect_s = json.dumps(s_json_detect_info)
    json_detect_f.write(json_detect_s)
    json_detect_f.close()
