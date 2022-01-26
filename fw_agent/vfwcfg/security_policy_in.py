import copy
from .vfw_base import Block 
from .vfw_base import Key
from .log_output import output

def sec_policy_in_rule_modify(obj, vrf, ip_proto, rule_id, **kw):
    try:
        s = obj.filter('vrf_index', vrf)
        if len(s):
            sss = s[0].filter('security_policy_in')
            if len(sss):
                if ip_proto == 'v4':
                    ss = sss[0].filter('ipv4')
                else:
                    ss = sss[0].filter('ipv6')
                if len(ss):
                    v = ss[0].filter('rule', rule_id)
                    if len(v):
                        for key, value in kw.items():
                            if not value:
                                continue
                            vv = v[0].filter('', key)
                            if len(vv):
                                output.info('vrf {} sec_policy_in ip_proto {} rule {} {} {} -> {}'.format(vrf, ip_proto, rule_id, key, vv[0].value, value))
                                vv[0].value = value 
                            else:
                                k = Key(key, value)
                                v[0].add(k)
                                output.info('vrf {} sec_policy_in ip_proto {} rule {} {} none -> {}'.format(vrf, ip_proto, rule_id, key, value))

    except Exception as e:
        output.exception(e)

def sec_policy_in_rule_is_exist(obj, vrf, ip_proto, rule_id):
    try:
        s = obj.filter('vrf_index', vrf)
        if len(s):
            sss = s[0].filter('security_policy_in')
            if len(sss):
                if ip_proto == 'v4':
                    ss = sss[0].filter('ipv4')
                else:
                    ss = sss[0].filter('ipv6')

                if len(ss):
                    v = ss[0].filter('rule', rule_id)
                    if len(v):
                        return True
        return False
    except Exception as e:
        output.exception(e)

def sec_policy_in_rule_get(obj, vrf, ip_proto='', rule_id=''):
    try:
        result = dict()
        proto = list()
        if ip_proto:
            proto.append(ip_proto)
        else:
            proto.append('v4')
            proto.append('v6')

        for i in proto:
            result[i] = list()

        vrf_conf = obj.filter('vrf_index', vrf)
        if len(vrf_conf):
            sec_p = vrf_conf[0].filter('security_policy_in')
            if len(sec_p):
                for p in proto:
                    ss = ''
                    if p == 'v4':
                        ss = sec_p[0].filter('ipv4')
                    else:
                        ss = sec_p[0].filter('ipv6')

                    if not len(ss):
                        continue

                    v = ''
                    if rule_id:
                        v = ss[0].filter('rule', rule_id)
                    else:
                        v = ss[0].filter('rule')

                    for r in v:
                        res = dict()
                        res[r.value] = dict()
                        for b in r.children:
                            res[r.value][b.name] = b.value

                        result[p].append(res)

        return result
    except Exception as e:
        output.exception(e)

def sec_policy_in_rule_add(obj, vrf, ip_proto, rule_id, **kw):
    try:
        log = 'vrf {} sec_policy_in ip_proto {} add rule {} -- '.format(vrf, ip_proto, rule_id)
        rule = Block('rule', rule_id)
        for key, value in kw.items():
            if value:
                k = Key(key, value)
                log += '{}:{} '.format(key,value)
                rule.add(k)

        s = obj.filter('vrf_index', vrf)
        if len(s):
            sss = s[0].filter('security_policy_in')
            if len(sss):
                ss = ''
                if ip_proto == 'v4':
                    ss = sss[0].filter('ipv4')
                else:
                    ss = sss[0].filter('ipv6')

                if len(ss):
                    output.info(log)
                    ss[0].add(rule)
    except Exception as e:
        output.exception(e)

def sec_policy_in_rule_del(obj, vrf, ip_proto, rule_id, **kw):
    try:
        s = obj.filter('vrf_index', vrf)
        if len(s):
            sss = s[0].filter('security_policy_in')
            if len(sss):
                ss = ''
                if ip_proto == 'v4':
                    ss = sss[0].filter('ipv4')
                else:
                    ss = sss[0].filter('ipv6')
                if len(ss):
                    v = ss[0].filter('rule', rule_id)
                    if len(v):
                        if len(kw):
                            tmp = copy.copy(v[0].children)
                            log = ''
                            del_item = True
                            for j in tmp:
                                if kw.get(j.name):
                                    del_item = False
                                    log += '{}:{} '.format(j.name, j.value)
                                    v[0].remove(j)
                            if log:
                                output.info('vrf {} sec_policy_in ip_proto {} del rule {} {}.'.format(vrf, ip_proto, rule_id, log))

                            if del_item:
                                ss[0].remove(v[0])
                                output.info('vrf {} sec_policy_in ip_proto {} del rule {}.'.format(vrf, ip_proto, rule_id))
    except Exception as e:
        output.exception(e)

def sec_policy_in_rule_order(obj, vrf, ip_proto, rule_id, pos='', base='', action=''):
    try:
        s = obj.filter('vrf_index', vrf)
        if len(s):
            sss = s[0].filter('security_policy_in')
            if len(sss):
                ss = ''
                if ip_proto == 'v4':
                    ss = sss[0].filter('ipv4')
                else:
                    ss = sss[0].filter('ipv6')

                if len(ss):
                    rule = ss[0].filter('rule', rule_id)
                    ss[0].children.remove(rule[0])
                    if pos == 'head':
                        ss[0].children.insert(0, rule[0])
                        output.info('vrf {} sec_policy_in ip_proto {} move rule {} head'.format(vrf, ip_proto, rule_id))

                    if pos == 'tail':
                        ss[0].children.append(rule[0])
                        output.info('vrf {} sec_policy_in ip_proto {} move rule {} tail'.format(vrf, ip_proto, rule_id))

                    if action == 'before':
                        base_rule = ss[0].filter('rule', base)
                        b_index = ss[0].children.index(base_rule[0])
                        ss[0].children.insert(b_index, rule[0])
                        output.info('vrf {} sec_policy_in ip_proto {} move rule {} before rule {}'.format(vrf, ip_proto, rule_id, base))

                    if action == 'after':
                        base_rule = ss[0].filter('rule', base)
                        b_index = ss[0].children.index(base_rule[0])
                        ss[0].children.insert(1+b_index, rule[0])
                        output.info('vrf {} sec_policy_in ip_proto {} move rule {} after rule {}'.format(vrf, ip_proto, rule_id, base))
    except Exception as e:
        output.exception(e)
