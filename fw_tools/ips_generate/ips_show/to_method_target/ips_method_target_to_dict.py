#!/usr/bin/env python
# -*- coding: UTF-8 -*- import os 
import sys
import time
import json


dict_all = dict()

def get_value(ss):
    r_len = 0
    for n in ss:
        p_len = ord(n)
        r_len = r_len * 256 + p_len
    return r_len

def get_type(t1):
    t = str(t1)
    if t1 == 2:
        t = 'name'
    if t1 == 25:
        t = 'name_cn'
    if t1 == 3:
        t = 'desc'
    if t1 == 26:
        t = 'desc_cn'
    if t1 == 6:
        t = 'type'
    if t1 == 84:
        t = 'sub_category'
    if t1 == 85:
        t = 'rule-id'
    if t1 == 95:
        t = 'sig_type'
    return t

def get_v(t1,l1,v1):
    if t1 == 84 or t1 ==85:
        if l1 > 0 and l1 % 4 != 0:
            print('invalid v1')
            return -1
        c1 = 0
        li = []
        while c1 < l1:
            v2 = get_value(v1[c1:c1+4])
            li.append(v2)
            c1 += 4
        return li
    elif t1 == 6 or t1 == 95:
        v2 = get_value(v1)
        if t1 == 95:
            if 1 == v2:
                return 'small'
            else:
                return 'big'
        return v2
    else:
        return v1

def get_rule_content(r_body, r_len, rule_id):
    cur = 0
    cur_len = 0
    
    while True:
        l1 = get_value(r_body[cur+2:cur+2+2])
        cur_len += (l1 + 4)
        if cur_len > r_len:
            print('invalid proc')
            break
        t1 = get_value(r_body[cur:cur+2])
        t = get_type(t1)
        v1 = r_body[cur+4:cur+4+l1]
        v = get_v(t1,l1,v1)
        if t == 'name' or t == 'type' or t == 'sub_category' or t == 'rule-id':
            dict_all[rule_id][t] = v

        if cur_len == r_len:
            #print('success proc')
            break
        cur += (l1 + 4)
    
if len(sys.argv) != 3:
    print('invalid input argument.example:body_method_or_target_file(IN),json_method_or_target_info(OUT)')
    sys.exit(0)

file_name = sys.argv[1]
rule_info_name = sys.argv[2]

f1 = open(file_name,'rb')
f2 = open(rule_info_name,'w')
f1.seek(0,2)
content_len = f1.tell()
print('file length is :' + str(content_len))
f1.seek(0,0)
cur_len = 0
categ_cnt = 0
body_len = 0

while True:
    f1.seek(8,1)
    msg_len = f1.read(2)
    r_len = get_value(msg_len)
    body_len += r_len
    cur_len += 12
    cur_len += r_len
    if cur_len > content_len:
        print('invalid end')
        break
    f1.seek(-10,1)
    
    a = f1.read(4)
    rule_id = get_value(a)
    version = f1.read(2)
    ver = get_value(version)
    engine = f1.read(2)
    eng = get_value(engine)

    if rule_id not in dict_all.keys():
        dict_all[rule_id] = dict()
    else:
        print('error: already exist')

    # skip len(2)+reserve(2)
    f1.seek(4,1)

    categ_cnt += 1
    rule_body = f1.read(r_len)
    get_rule_content(rule_body,r_len, rule_id)
    if cur_len == content_len:
        print('parse success.')
        break

dict_data = json.dumps(str(dict_all))
f2.write((dict_data))

f1.close()
f2.close()

print('all rule is :' + str(categ_cnt))
