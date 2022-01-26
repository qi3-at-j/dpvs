#!/usr/bin/env python

import sys
import os
import time
import json
import copy

vpath_ids = [23251,25313,34020,34059,34143,34146,34152,34172,34201,34203,34204,34205,34206,34207,34208,34209,34210,34211,34212,34213,34214,34215,34216,34217,34973,34974,35729,37051,42164,42181,42499,43167,43174,43372,43381,43385,43459,35,41,53,85,87,89,92,106,112,125,133,136,139,160,187,205,219,220,235,257,268,271,289,290,305,320,351,354,385,394,402,429,435,461,488,581,795,1011,1142,1215,1396,2134,2857,3261,3423,3547,3636,3962,4022,4050,4137,4220,4448,5007,5218,5447,6363,7351,7469,8523,9842,11078,11168,11354,12981,16302,17399,19142,20514,21804,22493,22546,22707,23125,23155,23168,23301,23336,23339,23478,23547,23559,23668,23750,23775,23882,23903,23906,23912,24159,24161,24166,24169,24172,24183,24195,24196,24203,24208,24217,24221,24225,24229,24283,24305,24317,24329,24330,24439,24523,24676,24677,24997,25137,25228,25310,25354,25439,25603,25606,26129,27279,29444,32375,32677,32678,32679,32680,32701,32702,32703,32704,32842,33189,33555,33561,33564,33680,33767,34301,34609,35281,35282,35562,35565,36270,37026,37085,37089,37120,37905,38055,42014,42079,42126,42381,42438,42449,42472,42488,42494,42848,42967,43428,43442,43662,43706,1,2,1833,3376,12071,14031,14763,15140,15947,18197,24343,24344,24349,24653,25105,33591,36910,24321,10425,23079,23147,23928,24184,24287,24357,24515,25593,25597,25616,31137,31503,212,297,2437,3538,4131,5170,7520,9122,9226,9910,9952,10115,10506,10523,11181,11469,11524,11657,12294,13007,13209,13412,14271,16490,16861,16981,21267,21651,23057,23135,23207,23590,24699,24700,24932,24933,24934,25016,25080,25161,25164,25166,25167,25212,30811,30878,31011,31033,31076,31537,32192,33551,33744,36909,37228,37,98,171,188,243,272,302,306,331,332,421,445,448,1170,4801,5422,5649,5752,7202,10887,11017,13972,14607,15074,21294,23061,23360,23473,23527,23543,23577,23803,24243,24276,24508,24727,25017,25018,25025,25210,25443,25458,25901,31416,32066,32354,32374,32380,32532,32681,32880,33045,33082,33177,33239,33416,33827,33958,33983,34038,34202,34280,34326,34334,34346,34588,34961,35170,35192,35203,35544,35598,36534,36636,36642,37070,37074,37142,37515,37903,38458,42095,42177,42215,42426,42439,42450,42508,42544,42628,42633,42935,43023,43079,43097,43150,43248,43249,43251,43427,44219,3842,9282,9516,10303,12489,14342,14767,17014,21565,24648,34225,34271,34592,35535,35597,35833,36405,37339,41468,42355,42414,42715,213,11162,15517,24242,24323,25605,33617,33823,35784,42396,316,443,21633,10918,25278,33727,33794,24829,25594,4642,23084,24311,24806,33665,481,23901,30464,33569,25602,25604,33835,16,1592,164,248,288,6267,36680,31692,4064,13498,24247,34353,34579,34862,42363,3903,6999,8893,14666,33592,33603,36646,237,367,23907,33575,34270,34276,34321,34673,35594,38300,38313,25587,17053,23115,24490,24826,24828,25224,25230,25279,25280,43219,43222,43250,751,1599,2011,4464,24821,299,24215,24892,33601,337,5359,6142,7223,10753,19800,24625,24680,24683,24688,24831,25133,25249,33933,32115]

if sys.getdefaultencoding() != 'utf-8':
    reload(sys)
    sys.setdefaultencoding('utf-8')

def trans_act(action):
    # act_suri = 'pass'
    act_suri = 'alert'
    if action == 18:
        act_suri = 'drop'
    elif action == 24:
        act_suri = 'reject'
    else:
        pass
    return act_suri

# 10  low
# 30  middle
# 60  high
# 90  serious

def trans_level(level):
    level_s = str(level)
    if level == 10:
        level_s = 'low'
    elif level == 30:
        level_s = 'middle'
    elif level == 60:
        level_s = 'high'
    elif level == 90:
        level_s = 'serious'
    else:
        print('not found level {}'.format(level))

    return level_s


def merge_desc_method_target(detect_dict, desc_dict, meth_dict, targ_dict):
    dict_all = dict()

    # merge base info
    for rule_id in desc_dict.keys():
        if rule_id not in dict_all.keys():
            dict_all[rule_id] = dict()
            dict_all[rule_id]['method'] = list()
            dict_all[rule_id]['target'] = list()
        else:
            print('error: rule {} already exist.'.format(rule_id))

        dict_all[rule_id]['name'] = desc_dict[rule_id].get('name')
        dict_all[rule_id]['name_cn'] = desc_dict[rule_id].get('name_cn')
        dict_all[rule_id]['desc'] = desc_dict[rule_id].get('desc')
        dict_all[rule_id]['desc_cn'] = desc_dict[rule_id].get('desc_cn')
        dict_all[rule_id]['level'] = desc_dict[rule_id].get('level')
        #dict_all[rule_id]['level'] = trans_level(desc_dict[rule_id].get('level'))
        dict_all[rule_id]['cnnvd'] = desc_dict[rule_id].get('cnnvd')
        dict_all[rule_id]['cve'] = desc_dict[rule_id].get('cve')
        dict_all[rule_id]['act'] = desc_dict[rule_id].get('act')
        #dict_all[rule_id]['act'] = trans_act(desc_dict[rule_id].get('act'))
        if rule_id in vpath_ids:
            dict_all[rule_id]['gid'] = 4
        else:
            dict_all[rule_id]['gid'] = 1

    # merge method 
    for meth_id in meth_dict.keys():
        if meth_dict[meth_id]['type'] == 1:
            name = meth_dict[meth_id]['name']
            for sub_id in meth_dict[meth_id]['sub_category']:
                sub_name = meth_dict[sub_id]['name']

                #print('Method:', name+'-'+sub_name)

                for rule_id in meth_dict[sub_id]['rule-id']:
                    if rule_id not in desc_dict.keys():
                        if rule_id != 0:
                            print('method error rule: {} not found in desc_dict.'.format(rule_id))
                            print(name + '-' + sub_name)
                        continue

                    dict_all[rule_id]['method'].append(name + '-' + sub_name)

    # merge target
    for targ_id in targ_dict.keys():
        if targ_dict[targ_id]['type'] == 1:
            name = targ_dict[targ_id]['name']
            for sub_id in targ_dict[targ_id]['sub_category']:
                sub_name = targ_dict[sub_id]['name']

                #print('Target:', name+'-'+sub_name)

                for rule_id in targ_dict[sub_id]['rule-id']:
                    if rule_id not in desc_dict.keys():
                        if rule_id != 0:
                            print('target error rule: {} not found in desc_dict.'.format(rule_id))
                            print(name + '-' + sub_name)
                        continue

                    dict_all[rule_id]['target'].append(name + '-' + sub_name)

    # process multiple ac_sig
    for rule_id in detect_dict.keys():
        sig_info = detect_dict[rule_id].get('sig')
        if sig_info and len(sig_info) > 1:
            if rule_id not in dict_all.keys():
                print('error detect_dict rule id {} not found.'.format(rule_id))
                continue

            if len(sig_info) < 1:
                print('not found ac sig')
                continue

            for i in range(1, len(sig_info)):
                mult_id = (i << 16) + rule_id 

                if mult_id in dict_all.keys():
                    print('error: {} {} already exist.'.format(rule_id, mult_id))
                    continue

                dict_all[mult_id] = copy.deepcopy(dict_all[rule_id])

    return dict_all


if __name__ == '__main__':
    if len(sys.argv) != 6:
        print("invalid input argument.example:detect_file(IN) desc_file(IN) method_file(IN) target_file(IN) output_file(OUT)")
        sys.exit(0)

    detect_f = open(sys.argv[1], 'r')
    detect_json = detect_f.read()
    detect_dict_s = json.loads(detect_json)
    detect_dict = eval(detect_dict_s)
    detect_f.close()

    desc_f = open(sys.argv[2], 'r')
    desc_json = desc_f.read()
    desc_dict_s = json.loads(desc_json)
    desc_dict = eval(desc_dict_s)
    desc_f.close()

    print('found {} rules in detect_dict'.format(len(detect_dict.keys())))
    print('found {} rules in desc_dict'.format(len(desc_dict.keys())))

    meth_f = open(sys.argv[3], 'r')
    meth_json = meth_f.read()
    meth_dict_s = json.loads(meth_json)
    meth_dict = eval(meth_dict_s)
    meth_f.close()

    targ_f = open(sys.argv[4], 'r')
    targ_json = targ_f.read()
    targ_dict_s = json.loads(targ_json)
    targ_dict = eval(targ_dict_s)
    targ_f.close()

    print('------merge ips rules start-----------')
    dict_all = merge_desc_method_target(detect_dict, desc_dict, meth_dict, targ_dict)
    print('------merge ips rules end-----------')

    #data_all = json.dumps((dict_all))
    data_all = json.dumps(str(dict_all))

    outp_f = open(sys.argv[5], 'w')
    outp_f.write(data_all)
    outp_f.close()

    print('\nprocessed {} rules, write to {}'.format(len(dict_all.keys()), sys.argv[5]))
