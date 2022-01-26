#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import os
import sys
import time
import json

proto_id_release = {
    1:'icmp',
    6:'tcp',
    17:'udp',
    11:'ftp',
    13:'ssh',
    15:'smtp',
    27:'tftp',
    31:'http',
    47:'ntp',
    54:'snmp',
    162:'nfs',
    196:'sip',
    574:'dns',
    598:'imap',
    1355:'rfb',
    2973:'rdp',
}

if sys.getdefaultencoding() != 'utf-8':
    reload(sys)
    sys.setdefaultencoding('utf-8')

def trans_distance(int_dis):
    str_dis = ''
    if int_dis >= 2147483648:
        str_dis = ('-'+str(4294967295-int_dis+1))
    else:
        str_dis = str(int_dis)
    return str_dis


def trans_protocol(proto_int,proto_id_name_dict):
    proto_name = ''

    #if proto_id_release.has_key(proto_int):
    #    proto_name = proto_id_release[proto_int]
    #else:
    #    proto_name = 'other'

    proto_int = str(proto_int)
    if proto_id_name_dict.has_key(proto_int):
        proto_name = proto_id_name_dict[proto_int]
    return proto_name

def trans_port(port_dict):
    port_s = ''
    if not port_dict:
        return 'any'
    if port_dict == 'any':
        return 'any'
    if port_dict.has_key('group'):
        port_list = port_dict['group']
        port_s = str(port_list)
    elif port_dict.has_key('range'):
        port_range = port_dict['range']
        p1 = port_range[0]
        p2 = port_range[1]
        port_s = '['+str(p1)+':'+str(p2)+']'
    return port_s

def trans_flow(sess_dir,sess_state):
    flow_str = 'flow:'
    if sess_state == 1:
        flow_str += 'established,'
    if sess_dir == 0:
        flow_str += 'to_server;'
    elif sess_dir == 1:
        flow_str += 'to_client;'
    else:
        if sess_state != 1:
            flow_str = ''
    return flow_str

def tran_http_method(http_method):
    if len(http_method) == 1:
        method_part = 'http.method; content:"' + http_method[0] + '"; nocase; '
    else:
        # '|'.join(xx)
        method_ls = ''
        for sig_method in http_method:
            method_ls += ('"' + sig_method + '"' + ',')
        method_s = method_ls[:-1]
        method_part = 'http.method; contentlist:' + method_s + '; '
        method_part += 'nocase; '
        #method_part = 'http.method; pcre:"/' + method_s + '/i";'
    return method_part

def gen_pre_part_rule(prot_int,msg,sess_dir,sess_state,http_method,proto_id_name_rel_f):
    pre_part_rule = 'pass'
    h_method = ''
    proto_name = trans_protocol(prot_int,proto_id_name_rel_f)
    pre_part_rule += ' ' + proto_name

    # src ip port -> dst ip port
    pre_part_rule += ' any any -> any any'
    pre_part_rule += ' ('
    if msg:
        msg_t = transf_hex_pattern(msg)
        msg_str = 'msg:"'+msg_t+'"; '
        pre_part_rule += msg_str
    if sess_state != None or sess_dir != None:
        flow_str = trans_flow(sess_dir,sess_state)
        pre_part_rule += flow_str

    if http_method:
        h_method = tran_http_method(http_method)
        # pre_part_rule += method_collect
    return pre_part_rule,h_method

def transf_hex_pattern_pcre(orig_pattern):
    tranc_pcre = ''
    for each_ch in orig_pattern:
        if each_ch == '"':
            tranc_pcre += r'\x22'
        elif each_ch == ';':
            tranc_pcre += r'\x3B'
        # for bug pcre:/(?:is)/
        #elif each_ch == ':':
        #    tranc_pcre += r'\x3A'
        #elif each_ch == '|':
        #    tranc_pcre += r'\x7C'
        else:
            tranc_pcre += each_ch
    return tranc_pcre

pcre_meta_char = ['\\', '^', '$', '*', '+', '?', '.', '|', '{', '}', '[', ']', '(', ')']

def transf_hex_pattern_pcre_to(orig_pattern):
    tranc_pcre = ''
    #print('orig:{} len {}'.format(orig_pattern, len(orig_pattern)))

    for each_ch in orig_pattern:
        if each_ch == '"':
            tranc_pcre += r'\x22'
        elif each_ch == ';':
            tranc_pcre += r'\x3B'
        elif each_ch == ':':
            tranc_pcre += r'\x3A'
        elif each_ch == '|':
            tranc_pcre += r'\x7C'
        else:
            xx = ord(each_ch)
            if xx <= 31 or xx >= 127:
                x = '\\x{:02X}'.format(xx)
            else:
                x = chr(xx)
                if x in pcre_meta_char:
                    tranc_pcre += '\\'

            tranc_pcre += x
    return tranc_pcre

def transf_hex_pattern(orig_pattern):
    if len(orig_pattern) == 0:
        return ''
    trans_str = ''
    fir_s = orig_pattern[0]
    oib = ord(fir_s)
    visable = 1
    if oib <= 31 or oib >= 127:
        visable = 0
        trans_str += '|'
    for each_ch in orig_pattern:
        oib = ord(each_ch)
        if oib <= 31 or oib >= 127 or each_ch == '"' or each_ch == ':' or each_ch == '|' or each_ch == ';' or each_ch == '\\':
            if visable == 1:
                trans_str += '|{:02X} '.format(oib)
            else:
                trans_str += '{:02X} '.format(oib)
            visable = 0
        else:
            if visable == 1:
                trans_str += chr(oib)
            else:
                trans_str += ('|' + chr(oib))
            visable = 1
    if oib <= 31 or oib >= 127 or each_ch == '"' or each_ch == ':' or each_ch == '|' or each_ch == ';' or each_ch == '\\':
        trans_str += '|'
    return trans_str

def gen_last_part_rule(sid,gid,rev):
    last_rule_str = 'sid:' + str(sid) + '; '
    last_rule_str += 'gid:' + str(gid) + '; '
    last_rule_str += ('rev:' + str(rev) + ';)')
    return last_rule_str

def check_high_sign(patt_s):
    h_sign = 0
    for each in patt_s:
        if each >= 'A' and each <= 'Z':
            h_sign = 1
            break
    return h_sign

def trans_host_high_low(patt_s):
    trans_low = ''
    for each_c in patt_s:
        if each_c >= 'A' and each_c <= 'Z':
            trans_low += chr(ord(each_c)+32)
        else:
            trans_low += each_c
    return trans_low

def trans_position_info(int_position,head_name,prot_int, sess_dir):
    suri_position = ''
    if int_position == 0:
        suri_position = 'http.uri'
    elif int_position == 1:
        suri_position = 'http.uri.raw'
    elif int_position == 2:
        suri_position = 'http.uri'
    elif int_position == 4:
        if prot_int == 31:
            suri_position = 'file_data'
    elif int_position == 5:
        suri_position = 'http.response_line'
    elif int_position == 6:
        if prot_int == 31:
            suri_position = 'http.header.raw'
    elif int_position == 7:
        suri_position = 'http.cookie'
    elif int_position == 9:
        suri_position = 'http.stat_code'
    elif int_position == 10:
        suri_position = 'http.stat_msg'
    elif int_position == 11:
        if prot_int == 31:
            suri_position = 'file_data'
    elif int_position == 12:
        suri_position = 'base64_data'
    elif int_position == 18:
        suri_position = 'http.uri'
    elif int_position == 3:
        if head_name == 'Content-Length':
            suri_position = 'http.content_len'
        elif head_name == 'Transfer-Encoding' or head_name == 'accept-charset' or \
             head_name == 'Content-Range' or \
             head_name == 'Range' or head_name == 'Authorization' or \
             head_name == 'Proxy-Authorization' or head_name == 'Expect' or \
             head_name == 'Cache-Control' or head_name == 'Accept-Ranges' or \
             head_name == 'Transfer_Encoding' or head_name == 'Content-Encoding' or \
             head_name == 'X-CMD' or head_name == 'Pragma' or \
             head_name == 'If-Modified-Since' or head_name == 'X-Requested-With' or \
             head_name == 'X-Umeng-Sdk' or head_name == 'clientAgent' or \
             head_name == 'bundleId' or head_name == 'DPUName' or \
             head_name == 'interface' or head_name == 'Sec-WebSocket-Protocol' or \
             head_name == 'm-ttid' or head_name == 'Mishop-Client-Id' or \
             head_name == 'bid' or head_name == 'X-MTEP-OS-Platform' or \
             head_name == 'Q-UA2' or head_name == 'X-Requseted-With' or \
             head_name == 'Origin' or head_name == 'Upgrade':
            suri_position = 'http.header.raw'
        elif head_name == 'Location':
            suri_position = 'http.location'
        elif head_name == 'User-Agent' or head_name == 'user-agent' or head_name == 'User-agent':
            if sess_dir == 2:
                sess_dir = 0
            suri_position = 'http.user_agent'
        elif head_name == 'Host' or head_name == 'host':
            suri_position = 'http.host'
        elif head_name == 'cookie' or head_name == 'Cookie':
            suri_position = 'http.cookie'
        elif head_name == 'Referer' or head_name == 'referer':
            suri_position = 'http.referer'
        elif head_name == 'Accept-Encoding':
            suri_position = 'http.accept_enc'
        elif head_name == 'Accept':
            suri_position = 'http.accept'
        elif head_name == 'Accept-Language':
            suri_position = 'http.accept_lang'
        elif head_name == 'Server':
            suri_position = 'http.server'
        elif head_name == 'Content-Disposition':
            suri_position = 'file_data'
        elif head_name == 'Connection':
            suri_position = 'http.connection'
        elif head_name == 'Content-type' or head_name == 'Content-Type':
            suri_position = 'http.content_type'
        else:
            print('not support header: {}'.format(head_name))
            pass
    else:
        suri_position = 'pkt_data'

    if suri_position == 'file_data' and sess_dir == 0:
        suri_position = 'http.request_body'
    return suri_position,sess_dir

def gen_inner_part_rule(ac_info,sess_dir, prot_int, mult_rid, sig_type):
    inner_part_rule = ''
    ac_pattern_list = ac_info['pattern']
    if len(ac_pattern_list) == 0:
        return inner_part_rule

    ac_position = ac_info.get('position')
    ac_head_name = ac_info.get('head_name')
    ac_distance = ac_info.get('distance')
    ac_depth = ac_info.get('depth')
    ac_within = ac_info.get('within')
    ac_offset = ac_info.get('offset')

    aera_content = ''
    nocase_s = ''
    if ac_position:
        aera_content, sess_dir_r = trans_position_info(ac_position, ac_head_name,prot_int, sess_dir)
        if sess_dir_r != sess_dir:
            sess_dir = sess_dir_r

        if aera_content:
            if aera_content == 'http.host':
                # inner_part_rule += (aera_content + '; nocase; ')
                nocase_s = 'nocase; '

            inner_part_rule += (aera_content + '; ')
    else:
        # no position
        inner_part_rule += 'pkt_data; '

    pattern_len = 0
    if len(ac_pattern_list) == 1:
        pattern_len = len(ac_pattern_list[0])
        trans_pattern = transf_hex_pattern(ac_pattern_list[0])
        # h_sign = check_high_sign(trans_pattern)
        # if not h_sign:
        #     nocase_s = ''
        # inner_part_rule += ('content:"' + trans_pattern + '"; ' + nocase_s)
        if nocase_s:
            trans_pattern = trans_host_high_low(trans_pattern)

        inner_part_rule += ('content:' + '"' + trans_pattern + '"; ')
        inner_part_rule += 'fast_pattern; '
        # inner_part_rule += ('content:"' + ac_pattern_list[0] + '"; ')
    else:
        trans_pattern_s =''
        for trans_pattern in ac_pattern_list:
            if pattern_len < len(trans_pattern):
                pattern_len = len(trans_pattern)
            trans_pattern = transf_hex_pattern(trans_pattern)
            if nocase_s:
                trans_pattern = trans_host_high_low(trans_pattern)
            trans_pattern_s += ('"' + trans_pattern + '"' + ',')

        trans_pattern = trans_pattern_s[:-1]
        # no append 'fast_pattern'
        inner_part_rule += ('contentlist:' + trans_pattern + '; ')


    if ac_distance != None:
        inner_part_rule += ('distance:' + trans_distance(ac_distance) + '; ')
    if ac_depth:
        if ac_depth < pattern_len:
            ac_depth = pattern_len
        inner_part_rule += ('depth:' + str(ac_depth) + '; ')
    if ac_within:
        if ac_within < pattern_len:
            ac_within = pattern_len
        inner_part_rule += ('within:' + str(ac_within) + '; ')
    if ac_offset:
        inner_part_rule += ('offset:' + str(ac_offset) + '; ')
    if ac_info.has_key('nocase'):
        inner_part_rule += 'nocase; '

    if sig_type == 2:
        inner_part_rule += 'startswith; '

    #if sig_type == 2:
    #    if ac_position:
    #        aera_content, sess_dir_r = trans_position_info(ac_position, ac_head_name, prot_int, sess_dir)
    #        if sess_dir_r != sess_dir:
    #            sess_dir = sess_dir_r

    #        if aera_content:
    #            inner_part_rule += (aera_content + '; ')
    #    else:
    #        # no position
    #        inner_part_rule += 'pkt_data; '

    #    if len(ac_pattern_list) > 1:
    #        dis0 = ''
    #        if True or ac_info.has_key('nocase'):
    #            dis0 += 'i'

    #        trans_pcre = ''
    #        for patt in ac_pattern_list:
    #            trans_s= transf_hex_pattern_pcre_to(patt)
    #            trans_pcre += '(' + '^' + trans_s + ')' + '|'

    #        inner_part_rule += ('pcre:"/' + trans_pcre[:-1] + '/' + dis0 +'"; ')

    #        #print("pcre pattern rule {} id {} count {} ".format(each_i, each_opt, len(pattern_list)))

    #    if len(ac_pattern_list) == 1:
    #        dis0 = ''
    #        if True or ac_info.has_key('nocase'):
    #            dis0 += 'i'

    #        trans_pcre = transf_hex_pattern_pcre_to(ac_pattern_list[0])
    #        #print("init:{}".format(ac_pattern_list[0]))
    #        #print("tran:{}".format(trans_pcre))

    #        inner_part_rule += ('pcre:"/' + '^' + trans_pcre + '/' + dis0 +'"; ')

    #    if ac_info.has_key('distance'):
    #        inner_part_rule += ('distance:' + trans_distance(ac_info['distance']) + '; ')
    #    if ac_info.has_key('within'):
    #        inner_part_rule += ('within:' + str(ac_info['within']) + '; ')
    #    if ac_info.has_key('depth'):
    #        inner_part_rule += ('depth:' + str(ac_info['depth']) + '; ')
    #    if ac_info.has_key('offset'):
    #        inner_part_rule += ('offset:' + str(ac_info['offset']) + '; ')
    #inner_part_rule += 'fast_pattern; '

    return inner_part_rule,aera_content,sess_dir

def gen_tail_part_rule(opt_info,sess_dir, prot_int, mult_rid, each_i):
    tail_part_rule = []
    for each_opt in opt_info:
        sigle_tail_part = ''
        if opt_info[each_opt]['pattern'] == []:
            continue
        aera_content = ''
        nocase_s = ''
        if opt_info[each_opt]['type'] == 'content':

            int_pos = opt_info[each_opt]['position'] if opt_info[each_opt].has_key('position') else None
            head_name = opt_info[each_opt]['head_name'] if opt_info[each_opt].has_key('head_name') else None

            if int_pos is not None:
                aera_content,sess_dir_r = trans_position_info(int_pos,head_name,prot_int, sess_dir)
                if sess_dir_r != sess_dir:
                    sess_dir = sess_dir_r

                if aera_content:
                    if aera_content == 'http.host':
                        nocase_s = 'nocase; '
                        # sigle_tail_part += (aera_content + '; nocase; ')

                    sigle_tail_part += (aera_content + '; ')
            else:
                # no position
                sigle_tail_part += 'pkt_data; '

            pattern_list = opt_info[each_opt]['pattern']
            pattern_len = 0
            if pattern_list:
                negated = ''
                if opt_info[each_opt].has_key('negative'):
                    negated = '!'

                if len(pattern_list) == 1:
                    pattern_len = len(pattern_list[0])
                    trans_pattern = transf_hex_pattern(pattern_list[0])
                    # h_sign = check_high_sign(trans_pattern)
                    # if not h_sign:
                    #     nocase_s = ''
                    # sigle_tail_part += ('content:' + negated + '"' + trans_pattern + '"; ' + nocase_s)
                    if nocase_s:
                        trans_pattern = trans_host_high_low(trans_pattern)
                    sigle_tail_part += ('content:' + negated + '"' + trans_pattern + '"; ')
                    # sigle_tail_part += ('content:' + negated + '"' + pattern_list[0] + '"; ')
                else:
                    trans_pattern_s =''
                    for trans_pattern in pattern_list:
                        if pattern_len < len(trans_pattern):
                            pattern_len = len(trans_pattern)
                        trans_pattern = transf_hex_pattern(trans_pattern)
                        if nocase_s:
                            trans_pattern = trans_host_high_low(trans_pattern)
                        trans_pattern_s += '"' + trans_pattern + '"' + ','

                    trans_pattern = trans_pattern_s[:-1]
                    sigle_tail_part += ('contentlist:' + negated + trans_pattern + '; ')

            if opt_info[each_opt].has_key('distance'):
                sigle_tail_part += ('distance:' + trans_distance(opt_info[each_opt]['distance']) + '; ')
            if opt_info[each_opt].has_key('within'):
                within = opt_info[each_opt]['within']
                if within < pattern_len:
                    within = pattern_len
                sigle_tail_part += ('within:' + str(within) + '; ')
            if opt_info[each_opt].has_key('depth'):
                depth = opt_info[each_opt]['depth']
                if depth < pattern_len:
                    depth = pattern_len
                sigle_tail_part += ('depth:' + str(depth) + '; ')
            if opt_info[each_opt].has_key('offset'):
                sigle_tail_part += ('offset:' + str(opt_info[each_opt]['offset']) + '; ')
            if opt_info[each_opt].has_key('nocase'):
                if head_name and head_name == 'Host':
                    print("rule {} http.host has nocae".format(mult_rid))
                    pass
                else:
                    sigle_tail_part += 'nocase; '

        if opt_info[each_opt]['type'] == 'regex':
            int_pos = opt_info[each_opt]['position'] if opt_info[each_opt].has_key('position') else None
            head_name = opt_info[each_opt]['head_name'] if opt_info[each_opt].has_key('head_name') else None
            if int_pos is not None:
                aera_content,sess_dir_r = trans_position_info(int_pos, head_name,prot_int, sess_dir)
                if sess_dir_r != sess_dir:
                    sess_dir = sess_dir_r

                if aera_content:
                    sigle_tail_part += (aera_content + '; ')
            else:
                # no position
                sigle_tail_part += 'pkt_data; '
            pattern_list = opt_info[each_opt]['pattern']
            # TODO no list
            if len(pattern_list) > 1:
                print("pcre pattern rule {} id {} count {} ".format(each_i, each_opt, len(pattern_list)))
            if pattern_list:
                dis0 = ''
                if opt_info[each_opt].has_key('nocase'):
                    dis0 += 'i'

                trans_pcre = transf_hex_pattern_pcre(pattern_list[0])

                sigle_tail_part += ('pcre:"/' + trans_pcre + '/' + dis0 +'"; ')

            if opt_info[each_opt].has_key('distance'):
                sigle_tail_part += ('distance:' + trans_distance(opt_info[each_opt]['distance']) + '; ')
            if opt_info[each_opt].has_key('within'):
                sigle_tail_part += ('within:' + str(opt_info[each_opt]['within']) + '; ')
            if opt_info[each_opt].has_key('depth'):
                sigle_tail_part += ('depth:' + str(opt_info[each_opt]['depth']) + '; ')
            if opt_info[each_opt].has_key('offset'):
                sigle_tail_part += ('offset:' + str(opt_info[each_opt]['offset']) + '; ')

        tail_part_rule.append(sigle_tail_part)
    return tail_part_rule,sess_dir

