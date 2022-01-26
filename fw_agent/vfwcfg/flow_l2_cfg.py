from .vfw_base import Block 
from .vfw_base import Key
from .log_output import output

def get_portlist(obj):
    try:
        portlist = list()
        s = obj.filter('netif_defs')
        if len(s):
            ss = s[0].filter('<init> device')
            for i in ss:
                portlist.append(i.value)

        return portlist
    except Exception as e:
        output.exception(e)

def get_vlanportlist(obj):
    try:
        portlist = list()
        s = obj.filter('flow_l2_cfg')
        if len(s):
            ss = s[0].filter('vlan')
            for i in ss:
                portlist.append(i.value)

        return portlist
    except Exception as e:
        output.exception(e)

def get_vlan_port_cfg(obj, if_name=''): 
    try:
        result = dict()

        l2_cfg = obj.filter('flow_l2_cfg')
        if len(l2_cfg):
            vlan_port_list = l2_cfg[0].filter('vlan', if_name)

            for i in vlan_port_list:
                result[i.value] = dict()
                result[i.value]['link'] = ''
                result[i.value]['id'] = ''

                item = i.filter('', 'link')
                if len(item):
                    result[i.value]['link'] = item[0].value

                item = i.filter('', 'id')
                if len(item):
                    result[i.value]['id'] = item[0].value

        return result
    except Exception as e:
        output.exception(e)

def vlan_port_is_exist(obj, if_name):
    try:
        s = obj.filter('flow_l2_cfg')
        if len(s):
            ss = s[0].filter('vlan', if_name)
            if len(ss):
                return True
            else:
                return False
    except Exception as e:
        output.exception(e)

def create_vlan_port(obj, action, if_name, link='', vlanid=''):
    try:
        s = obj.filter('flow_l2_cfg')
        if len(s):
            ss = s[0].filter('vlan', if_name)
            if not len(ss):
                if action == 'add':
                    link_k = Key('link', link)
                    id_k = Key('id', vlanid)
                    b = Block('vlan', if_name)
                    b.add(link_k)
                    b.add(id_k)
                    s[0].add(b)
                    output.info('add vlan-port {} link {} id {}'.format(if_name, link, vlanid))
            else:
                if action == 'del':
                    s[0].remove(ss[0])
                    output.info('delete vlan-port {}'.format(if_name))
    except Exception as e:
        output.exception(e)

def set_port_ip_list(obj, if_name, action, **kw):
    try:
        l2_cfg = obj.filter('flow_l2_cfg')
        if len(l2_cfg):
            port = None

            res = l2_cfg[0].filter('port', if_name)
            if not len(res):
                if action == 'add':
                    b = Block('port', if_name)
                    l2_cfg[0].add(b)
                    port = b
            else:
                port = res[0]

            if port:
                ip_list = port.filter('', 'ip')
                ip6_list = port.filter('', 'ip6')
                for k,v in kw.items():
                    found = 0
                    for i in ip_list:
                        if i.name == k and i.value == v:
                            if action == 'add':
                                # exist
                                found = 1
                                break
                            else:
                                port.remove(i)
                                ip_list.remove(i)
                                found = 1
                                output.info('remove port {} {} {}'.format(if_name, k, v))
                                break
                        else:
                            pass

                    if found:
                        continue

                    found = 0
                    for i in ip6_list:
                        if i.name == k and i.value == v:
                            if action == 'add':
                                # exist
                                found = 1
                                break
                            else:
                                port.remove(i)
                                ip6_list.remove(i)
                                found = 1
                                output.info('remove port {} {} {}'.format(if_name, k, v))
                                break
                    if found:
                        continue

                    if action == 'add':
                        ip = Key(k, v)
                        port.add(ip)
                        output.info('add port {} {} {}'.format(if_name, k, v))
    except Exception as e:
        output.exception(e)

def get_port_ip_list(obj, if_name):
    try:
        port_list = list()

        if if_name:
            port_list.append(if_name)
        else:
            port_list = get_portlist(obj)

        result = dict()

        l2_cfg = obj.filter('flow_l2_cfg')

        for name in port_list:
            result[name] = dict()
            result[name]['ip'] = ''
            result[name]['ip6'] = ''

            if len(l2_cfg):
                res = l2_cfg[0].filter('port', name)
                if len(res):
                    port = res[0]
                    ip_list = list()
                    ip6_list = list()
                    ips = port.filter('', 'ip')
                    ip6s = port.filter('', 'ip6')

                    for i in ips:
                        ip_list.append(i.value)

                    result[name]['ip'] = ','.join(ip_list)

                    for i in ip6s:
                        ip6_list.append(i.value)

                    result[name]['ip6'] = ','.join(ip6_list)

        return result
    except Exception as e:
        output.exception(e)

def rate_limit_set(obj, vrf, **kw):
    try:
        limit = ''
        l2_cfg = obj.filter('flow_l2_cfg')
        if len(l2_cfg):
            rate_limit = l2_cfg[0].filter('rate_limit', vrf)
            if len(rate_limit):
                limit = rate_limit[0]
            else:
                return ''
        else:
            return ''

        for k,v in kw.items():
            i = limit.filter('', k)
            if len(i):
                if i[0].value != v:
                    output.info('vrf {} rate_limit {} {} -> {}'.format(vrf, k, i[0].value, v))
                    i[0].value = v
            else:
                key = Key(k, v)
                limit.add(key)
                output.info('vrf {} rate_limit {} none -> {}'.format(vrf, k, v))
    except Exception as e:
        output.exception(e)

def rate_limit_get(obj, vrf):
    try:
        result = dict()
        result['rate_limit'] = dict()

        l2_cfg = obj.filter('flow_l2_cfg')
        if len(l2_cfg):
            rate_limit = l2_cfg[0].filter('rate_limit', vrf)
            if len(rate_limit):
                for i in rate_limit[0].children:
                    result['rate_limit'][i.name] = i.value

        return result['rate_limit']
    except Exception as e:
        output.exception(e)
