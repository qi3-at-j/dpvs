import copy
from .vfw_base import Block 
from .vfw_base import Key
from .log_output import output

def sec_policy_subnet_add(obj, vrf, ip_proto, ip):
    try:
        vrf_conf = obj.filter('vrf_index', vrf)
        if len(vrf_conf):
            net = vrf_conf[0].filter('subnet')
            if len(net):
                ips = ''
                k_name = ''

                if ip_proto == 'v4':
                    k_name = 'ip'
                    ips = net[0].filter('', 'ip')
                else:
                    k_name = 'ipv6'
                    ips = net[0].filter('', 'ipv6')

                if len(ips):
                    ip_list = ip.split(',')
                    for i in ip_list:
                        found = False
                        for b in ips:
                            if b.value == i.strip():
                                found = True
                                break

                        if not found:
                            item = Key(k_name, i.strip())
                            net[0].add(item)
                            output.info('vrf {} subnet {} add {}'.format(vrf, k_name, i.strip()))
                else:
                    ip_list = ip.split(',')
                    for i in ip_list:
                        item = Key(k_name, i.strip())
                        net[0].add(item)
                        output.info('vrf {} subnet {} add {}'.format(vrf, k_name, i.strip()))

    except Exception as e:
        output.exception(e)

def sec_policy_subnet_del(obj, vrf, ip_proto, ip):
    try:
        vrf_conf = obj.filter('vrf_index', vrf)
        if len(vrf_conf):
            net = vrf_conf[0].filter('subnet')
            if len(net):
                ips = ''
                if ip_proto == 'v4':
                    ips = net[0].filter('', 'ip')
                else:
                    ips = net[0].filter('', 'ipv6')

                if len(ips):
                    ip_list = ip.split(',')
                    for i in ip_list:
                        for b in ips:
                            if b.value == i.strip():
                                net[0].remove(b)
                                output.info('vrf {} subnet {} del {}'.format(vrf, b.name, b.value))
                                break
    except Exception as e:
        output.exception(e)

def sec_policy_subnet_get(obj, vrf, ip_proto=''):
    try:
        result = dict()
        result[vrf] = dict()
        result[vrf]['subnet'] = dict()

        proto = list()

        if ip_proto == 'v4':
            proto.append('ip')
            result[vrf]['subnet']['ip'] = list()

        if ip_proto == 'v6':
            proto.append('ipv6')
            result[vrf]['subnet']['ipv6'] = list()

        if not ip_proto:
            proto.append('ip')
            proto.append('ipv6')
            result[vrf]['subnet']['ip'] = list()
            result[vrf]['subnet']['ipv6'] = list()

        vrf_conf = obj.filter('vrf_index', vrf)
        if len(vrf_conf):
            net = vrf_conf[0].filter('subnet')
            if len(net):
                for p in proto:
                    ips = net[0].filter('', p)
                    for b in ips:
                        result[vrf]['subnet'][p].append(b.value)
        return result
    except Exception as e:
        output.exception(e)
