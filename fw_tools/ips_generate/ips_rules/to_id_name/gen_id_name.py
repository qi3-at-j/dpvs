#!/usr/bin/env python
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

def get_type_bk(t1):
    ts =  '    T: '
    t = str(t1)
    if t1 == 12:
        t = 'priority(12)'
    if t1 == 15:
        t = 'solution(15)'
    if t1 == 30:
        t = 'solution_cn(30)'
    if t1 == 271:
        t = 'refernce(271)'
    if t1 == 3:
        t = 'desc(3)'
    if t1 == 26:
        t = 'desc_cn(26)'
    if t1 == 4:
        t = 'enable(4)'
    if t1 == 2:
        t = 'name(2)'
    if t1 == 25:
        t = 'name_cn(25)'
    if t1 == 10:
        t = 'fidelity(10)'
    if t1 == 5:
        t = 'publish(5)'
    if t1 == 68:
        t = 'level(68)'
    if t1 == 64:
        t = 'action(64)'
    if t1 == 11:
        t = 'performance(11)'
    if t1 == 8:
        t = 'encrypt(8)'
    if t1 == 7:
        t = 'tunnel(7)'
    if t1 == 27:
        t = 'popular(27)'
    if t1 == 28:
        t = 'detect_length(28)'
    if t1 == 36:
        t = 'factory(36)'
    if t1 == 37:
        t = 'flow-behavior(37)'
    if t1 == 95:
        t = 'sig_type(95)'
    if t1 == 1:
        t = 'sid(1)'
        ts = '        T: '
    if t1 == 72:
        t = 'cve(72)'
        ts = '        T: '
    if t1 == 79:
        t = 'bid(79)'
        ts = '        T: '
    if t1 == 86:
        t = 'cnnvd(86)'
        ts = '        T: '
    if t1 == 74:
        t = str(t1)+'(74)'
        ts = '        T: '
    ts += t
    return ts

def get_v_bk(t1,l1,v1,rule_id,rule_name_dict):
    if t1 == 12 or t1 ==10 or t1 == 68 or t1 == 64 or t1 ==11 or t1 == 4 or t1 == 7 or t1 == 8 or t1 == 90 or t1 == 27:
        if l1 != 1:
            print 'invalid v1'
            return -1
        c1 = ord(v1)
        if t1 == 4 or t1 == 7 or t1 ==8:
            en1 = 'false'
            if c1 == 1:
               en1 = 'true'
            f2.write('    V: ' + str(en1) +'\r\n')
            return
        f2.write('    V: ' + str(c1) +'\r\n')
        return
    elif t1 == 271:
        #v_ref = '\r\n'
        f2.write('    V: {' + '\r\n')
        get_rule_content(v1,l1,f2,rule_id,rule_name_dict)
        f2.write('    }' + '\r\n')
    elif t1 == 1 or t1 == 79 or t1 == 95 or t1 == 36 or t1 == 37 or t1 == 28:
        c1 = 0
        c1 = get_value(v1)
        f2.write('    V: ' + str(c1) +'\r\n')
        return
    elif t1 == 2:
        rule_name_dict[rule_id] = str(v1)
        f2.write('    V: ' + str(v1) +'\r\n')
    else:
        f2.write('    V: ' + str(v1) +'\r\n')
        return

def get_type(t1):
    ts =  '    T: '
    t = str(t1)
    if t1 == 3:
        t = 'desc(3)'
    elif t1 == 26:
        t = 'desc_cn(26)'
    elif t1 == 2:
        t = 'name(2)'
    elif t1 == 25:
        t = 'name_cn(25)'
    else:
        ts = ''
        t = ''
        pass
    ts += t
    return ts

def get_v(t1,l1,v1,rule_id,rule_name_dict):
    if t1 == 12 or t1 ==10 or t1 == 68 or t1 == 64 or t1 ==11 or t1 == 4 or t1 == 7 or t1 == 8 or t1 == 90 or t1 == 27:
        pass
    elif t1 == 271:
        #v_ref = '\r\n'
        pass
    elif t1 == 1 or t1 == 79 or t1 == 95 or t1 == 36 or t1 == 37 or t1 == 28:
        #c1 = 0
        #c1 = get_value(v1)
        #f2.write('    V: ' + str(c1) +'\r\n')
        #return
        pass
    elif t1 == 2:
        rule_name_dict[rule_id] = str(v1)
        f2.write('    V: ' + str(v1) +'\r\n')
    else:
        f2.write('    V: ' + str(v1) +'\r\n')
        return

def get_rule_content(r_body,r_len,f2,rule_id,rule_name_dict):
    cur = 0
    cur_len = 0
    
    if r_len == 0:
        return

    while True:
        # get len
        l1 = get_value(r_body[cur+2:cur+2+2])
        cur_len += (l1 + 4)
        if cur_len > r_len:
            print 'invalid proc' + str(rule_id)
            print r_body
            print r_len
            break

        # get type
        t1 = get_value(r_body[cur:cur+2])
        #t = get_type(t1)
        t = get_type_bk(t1)
        if t:
            f2.write(t)
            f2.write('    L: ' + str(l1))

        # get value
        v1 = r_body[cur+4:cur+4+l1]

        #get_v(t1,l1,v1,rule_id,rule_name_dict)
        get_v_bk(t1,l1,v1,rule_id,rule_name_dict)
        if cur_len == r_len:
            #print 'success proc'
            break
        cur += (l1 + 4)

if len(sys.argv) != 4:
    print "invalid input argument.example:body_apr_desc_file(IN),desc_info_file(OUT)，json_id_name(OUT)"
    sys.exit(0)
file_name = sys.argv[1]
rule_info_name = sys.argv[2]
rulen_desc_name = sys.argv[3]
f1 = open(file_name,'rb')
f2 = open(rule_info_name,'w+')
f3 = open(rulen_desc_name,'w+')
f1.seek(0,2)
content_len = f1.tell()
print 'file length is :' + str(content_len)
f1.seek(0,0)
cur_len = 0
categ_cnt = 0
body_len = 0
rule_name_dict = {}

while True:
    f1.seek(8,1)
    len_1 = f1.read(2)
    r_len = get_value(len_1)
    body_len += r_len
    cur_len += 12
    cur_len += r_len
    if cur_len > content_len:
        print 'invalid end'
        break
    f1.seek(-10,1)
    
    a = f1.read(4)
    rule_id = get_value(a)
    version = f1.read(2)
    ver = get_value(version)
    engine = f1.read(2)
    eng = get_value(engine)
    #print 'rule_id is: ' + str(rule_id)
    str_tmp = 'ID: ' + str(rule_id) + ', version: ' + str(ver) + ', engine: ' + str(eng) + ', length: ' + str(r_len) + '\r\n'
    f2.write(str_tmp)

    f1.seek(-8,1)
    li = []
    b = f1.read(12)
    for m in b:
        p_len = ord(m)
        li.append(p_len)

    categ_cnt += 1
    rule_body = f1.read(r_len)
    get_rule_content(rule_body,r_len,f2,rule_id,rule_name_dict)
    if cur_len == content_len:
        print 'parse success.'
        break

print 'all rule is :' + str(categ_cnt)
print 'all body length is :' + str(body_len)
f2.write("###############################\r\n    all rule numbers is " + str(categ_cnt) + "\r\n###############################")
jr_name =json.dumps(rule_name_dict)
f3.write(str(jr_name))
f1.close()
f2.close()
f3.close()


