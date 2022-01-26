from .log_output import output

class aspf_policy_id_get():
    def __init__(self, obj, vrf):
        try:
            s = obj.filter('vrf_index', vrf)
            if len(s):
                ss = s[0].filter('aspf_policy')
                if len(ss):
                    v = ss[0].filter('', 'detect')
                    if len(v):
                        self.detect = v[0].value
                    else:
                        self.detect = ''
                    v = ss[0].filter('', 'tcp_syn_check')
                    if len(v):
                        self.tcp_syn_check = v[0].value
                    else:
                        self.tcp_syn_check = ''
        except Exception as e:
            output.exception(e)

def aspf_policy_detect_insert(obj, vrf, protocol):
    try:
        s = obj.filter('vrf_index', vrf)
        if len(s):
            ss = s[0].filter('aspf_policy')
            if len(ss):
                v = ss[0].filter('', 'detect')
                if len(v):
                    tmp = v[0].value.split()
                    if protocol not in tmp:
                        tmp.append(protocol)
                        v[0].value = ' '.join(tmp)
                        output.info('vrf {} aspf_policy insert {}'.format(vrf, protocol))
    except Exception as e:
        output.exception(e)

def aspf_policy_detect_remove(obj, vrf, protocol):
    try:
        s = obj.filter('vrf_index', vrf)
        if len(s):
            ss = s[0].filter('aspf_policy')
            if len(ss):
                v = ss[0].filter('', 'detect')
                if len(v):
                    tmp = v[0].value.split()
                    if protocol in tmp:
                        tmp.remove(protocol)
                        v[0].value = ' '.join(tmp)
                        output.info('vrf {} aspf_policy remove {}'.format(vrf, protocol))
    except Exception as e:
        output.exception(e)

def aspf_policy_modify(obj, vrf, name, value):
    try:
        s = obj.filter('vrf_index', vrf)
        if len(s):
            ss = s[0].filter('aspf_policy')
            if len(ss):
                v = ss[0].filter('', name)
                if len(v):
                    output.info('vrf {} aspf {} {} -> {}'.format(vrf, name, v[0].value, value))
                    v[0].value = value
    except Exception as e:
        output.exception(e)
