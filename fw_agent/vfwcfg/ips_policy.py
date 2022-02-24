from .vfw_base import Block 
from .vfw_base import Key
from .log_output import output

def ips_policy_modify(obj, vrf, rule_id, value):
    try:
        s = obj.filter('vrf_index', vrf)
        if len(s):
            ss = s[0].filter('ips_policy')
            if len(ss):
                v = ss[0].filter('rule', rule_id)
                if len(v):
                    vv = v[0].filter('', 'action')
                    if len(vv):
                        output.info('vrf {} ips_policy {} action {} -> {}'.format(vrf, rule_id, vv[0].value, value))
                        vv[0].value = value 
                else:
                    rule = Block('rule', rule_id)
                    k = Key('action', value)
                    rule.add(k)
                    ss[0].add(rule)
                    output.info('vrf {} ips_policy {} action default -> {}'.format(vrf, rule_id, value))
    except Exception as e:
        output.exception(e)


def ips_policy_get(obj, vrf, rule_id):
    action = ""
    s = obj.filter('vrf_index', vrf)
    if len(s):
        ss = s[0].filter('ips_policy')
        if len(ss):
            v = ss[0].filter('rule', rule_id)
            if len(v):
                vv = v[0].filter('', 'action')
                if len(vv):
                    action = vv[0].value
    return action

def ips_policy_delete(obj, vrf, rule_id):
    try:
        s = obj.filter('vrf_index', vrf)
        for ss in s:
            v = ss.filter('ips_policy')
            if len(v):
                vv = v[0].filter('rule', rule_id)
                if len(vv):
                    vvv = vv[0].filter('', 'action')
                    if len(vvv):
                        output.info('vrf {} ips_policy {} action {} -> default'.format(vrf, rule_id, vvv[0].value))
                    v[0].remove(vv[0])
    except Exception as e:
        output.exception(e)

def ips_policy_delete_all(obj):
    try:
        s = obj.filter('vrf_index')
        for ss in s:
            v = ss.filter('ips_policy')
            if len(v):
                vv = v[0].filter('rule')
                for vvv in vv:
                    v[0].remove(vvv)
    except Exception as e:
        output.exception(e)

def ips_cfg_set(obj, vrf, **kw):
    try:
        s = obj.filter('vrf_index', vrf)
        if len(s):
            cfg = s[0].filter('dpi_cfg')
            if len(cfg):
                for k,v in kw.items():
                    i = cfg[0].filter('', k)
                    if len(i):
                        if i[0].value != v:
                            output.info('vrf {} dpi_cfg {} {} -> {}'.format(vrf, k, i[0].value, v))
                            i[0].value = v
                    else:
                        j = Key(k,v)
                        cfg[0].add(j)
                        output.info('vrf {} dpi_cfg {} none -> {}'.format(vrf, k, v))
    except Exception as e:
        output.exception(e)

def ips_cfg_get(obj, vrf):
    try:
        result = dict()
        result[vrf] = dict()

        s = obj.filter('vrf_index', vrf)
        if len(s):
            cfg = s[0].filter('dpi_cfg')
            if len(cfg):
                for i in cfg[0].children:
                    result[vrf][i.name] = i.value

        return result[vrf]
    except Exception as e:
        output.exception(e)


