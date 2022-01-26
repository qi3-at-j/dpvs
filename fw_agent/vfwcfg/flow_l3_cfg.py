import copy
from .vfw_base import Block 
from .vfw_base import Key
from .log_output import output


################ route cfg start #####################################
# proto: v4 v6 / dip / netmask / gw / port / type
def route_is_exist(obj, vrf, proto, **kw):
    try:
        l3_cfg = obj.filter('flow_l3_cfg')
        if len(l3_cfg):
            route = l3_cfg[0].filter('route', vrf)
            if len(route):
                v = route[0].filter(proto)
                for r in v:
                    for x in r.children:
                        if kw.get(x.name) != x.value:
                            break
                    else:
                        return True

        return False
    except Exception as e:
        output.exception(e)

def route_add(obj, vrf, proto, **kw):
    try:
        l3_cfg = obj.filter('flow_l3_cfg')
        if len(l3_cfg):
            route = l3_cfg[0].filter('route', vrf)
            if len(route):
                new_r = Block(proto)
                msg = ''
                for k,v in kw.items():
                    key = Key(k, v)
                    new_r.add(key)
                    msg += '{} {} '.format(k, v)

                route[0].add(new_r)
                output.info('add vrf {} {} route {}'.format(vrf, proto, msg.strip()))
    except Exception as e:
        output.exception(e)

def route_del(obj, vrf, proto, **kw):
    try:
        l3_cfg = obj.filter('flow_l3_cfg')
        if len(l3_cfg):
            route = l3_cfg[0].filter('route', vrf)
            if len(route):
                v = route[0].filter(proto)
                for r in v:
                    msg = ''
                    for x in r.children:
                        if x.name != 'gw':
                            if kw.get(x.name) != x.value:
                                break
                            else:
                                msg += '{} {} '.format(x.name, x.value)
                    else:
                        # found
                        route[0].remove(r)
                        output.info('delete vrf {} {} route {}'.format(vrf, proto, msg.strip()))
                        return True
        return False
    except Exception as e:
        output.exception(e)

def route_del_all(obj, vrf, proto=''):
    try:
        proto_l = list()
        if proto:
            proto_l.append(proto)
        else:
            proto_l.append('v4')
            proto_l.append('v6')

        l3_cfg = obj.filter('flow_l3_cfg')
        if len(l3_cfg):
            route = l3_cfg[0].filter('route', vrf)
            if len(route):
                for pro in proto_l:
                    xx = route[0].filter(pro)
                    for x in xx:
                        route[0].remove(x)

                    if len(xx):
                        output.info('delete vrf {} all {} route'.format(vrf, pro))
    except Exception as e:
        output.exception(e)

def route_get_all(obj, vrf, proto=''):
    try:
        result = dict()
        result[vrf] = dict()

        proto_l = list()
        if proto:
            proto_l.append(proto)
            result[vrf][proto] = list()
        else:
            proto_l.append('v4')
            proto_l.append('v6')
            result[vrf]['v4'] = list()
            result[vrf]['v6'] = list()

        l3_cfg = obj.filter('flow_l3_cfg')
        if len(l3_cfg):
            route = l3_cfg[0].filter('route', vrf)
            if len(route):
                for pro in proto_l:
                    v = route[0].filter(pro)
                    for r in v:
                        key = dict()
                        for x in r.children:
                            key[x.name] = x.value

                        result[vrf][pro].append(key)

        return result
    except Exception as e:
        output.exception(e)

################ route cfg end  ######################################

################ vxlan cfg start #####################################
def vxlan_is_exist(obj, vni):
    try:
        l3_cfg = obj.filter('flow_l3_cfg')
        if len(l3_cfg):
            vxlan = l3_cfg[0].filter('vxlan', vni)
            if len(vxlan):
                    return True
        return False
    except Exception as e:
        output.exception(e)

def vxlan_add(obj, vni, proto, **kw):
    try:
        l3_cfg = obj.filter('flow_l3_cfg')
        if len(l3_cfg):
            new_r = Block(proto)
            msg = ''
            for k,v in kw.items():
                msg += k
                msg += ' '
                for i in v.split(','):
                    key = Key(k, i.strip())
                    new_r.add(key)
                    msg += '{} '.format(i.strip())

            vxlan = Block('vxlan', vni)
            vxlan.add(new_r)

            l3_cfg[0].add(vxlan)
            output.info('add vxlan {} proto {} {}'.format(vni, proto, msg.strip()))
    except Exception as e:
        output.exception(e)

def vxlan_del(obj, vni):
    try:
        l3_cfg = obj.filter('flow_l3_cfg')
        if len(l3_cfg):
            vxlan = l3_cfg[0].filter('vxlan', vni)
            if len(vxlan):
                l3_cfg[0].remove(vxlan[0])
                output.info('delete vxlan {}'.format(vni))
                return True

        return False
    except Exception as e:
        output.exception(e)

def vxlan_get_all(obj, vni=''):
    try:
        result = dict()

        l3_cfg = obj.filter('flow_l3_cfg')
        if len(l3_cfg):
            vxlan = l3_cfg[0].filter('vxlan', vni)
            if len(vxlan) == 0:
                if vni:
                    result[vni] = dict()

            for v in vxlan:
                res = dict()
                for x in v.children:
                    res[x.name] = dict()
                    for k in x.children:
                        res[x.name][k.name] = k.value

                result[v.value] = res

        return result
    except Exception as e:
        output.exception(e)

################ vxlan cfg end  ######################################

################ vrf_bind cfg start ##################################
def vrf_bind_field_is_exist(vrf_bind, key, value):
    try:
        keys = vrf_bind.filter('', key)
        if len(keys):
            for k in keys:
                if k.value == value:
                    return True
        return False
    except Exception as e:
        output.exception(e)

def vrf_bind_set(obj, vrf, **kw):
    try:
        l3_cfg = obj.filter('flow_l3_cfg')
        if len(l3_cfg):
            vrf_bind = l3_cfg[0].filter('vrf_bind', vrf)
            if len(vrf_bind):
                msg = ''
                for k,v in kw.items():
                    msg += k
                    msg += ' '
                    for i in v.split(','):
                        if not vrf_bind_field_is_exist(vrf_bind[0], k, i):
                            x = Key(k, i)
                            vrf_bind[0].add(x)
                            msg += '{} '.format(i.strip())

                output.info('add vrf-bind vrf {} {}'.format(vrf, msg.strip()))
    except Exception as e:
        output.exception(e)

def vrf_bind_get(obj, vrf):
    try:
        result = dict()
        result[vrf] = dict()

        l3_cfg = obj.filter('flow_l3_cfg')
        if len(l3_cfg):
            vrf_bind = l3_cfg[0].filter('vrf_bind', vrf)
            if len(vrf_bind):
                for k in vrf_bind[0].children:
                    if k.name in result[vrf]:
                        result[vrf][k.name].append(k.value)
                    else:
                        result[vrf][k.name] = list()
                        result[vrf][k.name].append(k.value)

        return result
    except Exception as e:
        output.exception(e)

def vrf_bind_del(obj, vrf, **kw):
    try:
        l3_cfg = obj.filter('flow_l3_cfg')
        if len(l3_cfg):
            vrf_bind = l3_cfg[0].filter('vrf_bind', vrf)
            if len(vrf_bind):
                msg = ''
                for k,v in kw.items():
                    msg += k
                    msg += ' '
                    for i in v.split(','):
                        for j in vrf_bind[0].children:
                            if j.name == k and j.value == i.strip():
                                vrf_bind[0].remove(j)
                                msg += '{} '.format(i.strip())

                output.info('delete vrf-bind vrf {} {}'.format(vrf, msg.strip()))
    except Exception as e:
        output.exception(e)

def vrf_bind_del_all(obj, vrf):
    try:
        l3_cfg = obj.filter('flow_l3_cfg')
        if len(l3_cfg):
            vrf_bind = l3_cfg[0].filter('vrf_bind', vrf)
            if len(vrf_bind):
                tmp = copy.copy(vrf_bind[0].children)
                for j in tmp:
                    vrf_bind[0].remove(j)
                output.info('delete vrf-bind vrf {} all'.format(vrf))
    except Exception as e:
        output.exception(e)

################ vrf_bind cfg end ####################################

################ arp cfg start #######################################
def arp_is_exist(obj, vrf, proto, **kw):
    try:
        l3_cfg = obj.filter('flow_l3_cfg')
        if len(l3_cfg):
            arp = l3_cfg[0].filter('arp', vrf)
            if len(arp):
                v = arp[0].filter(proto)
                for r in v:
                    for x in r.children:
                        if kw.get(x.name) != x.value:
                            break
                    else:
                        return True

        return False
    except Exception as e:
        output.exception(e)

def arp_add(obj, vrf, proto, **kw):
    try:
        l3_cfg = obj.filter('flow_l3_cfg')
        if len(l3_cfg):
            arp = l3_cfg[0].filter('arp', vrf)
            if len(arp):

                new_r = Block(proto)
                msg = ''
                for k,v in kw.items():
                    key = Key(k, v)
                    new_r.add(key)
                    msg += '{} {} '.format(k, v)

                arp[0].add(new_r)
                output.info('add arp vrf {} proto {} {}'.format(vrf, proto, msg.strip()))
        return False
    except Exception as e:
        output.exception(e)

def arp_del(obj, vrf, proto, **kw):
    try:
        l3_cfg = obj.filter('flow_l3_cfg')
        if len(l3_cfg):
            arp = l3_cfg[0].filter('arp', vrf)
            if len(arp):
                v = arp[0].filter(proto)
                for r in v:
                    msg = ''
                    for x in r.children:
                        if x.name != 'mac':
                            if kw.get(x.name) != x.value:
                                break
                            else:
                                msg += '{} {} '.format(x.name, x.value)
                    else:
                        # found
                        arp[0].remove(r)
                        output.info('delete arp vrf {} proto {} {}'.format(vrf, proto, msg.strip()))
                        return True
        return False
    except Exception as e:
        output.exception(e)

def arp_del_all(obj, vrf, proto=''):
    try:
        proto_l = list()
        if proto:
            proto_l.append(proto)
        else:
            proto_l.append('v4')
            proto_l.append('v6')

        l3_cfg = obj.filter('flow_l3_cfg')
        if len(l3_cfg):
            arp = l3_cfg[0].filter('arp', vrf)
            if len(arp):
                for pro in proto_l:
                    xx = arp[0].filter(pro)
                    for x in xx:
                        arp[0].remove(x)

                    if len(xx):
                        output.info('delete arp vrf {} all proto {}'.format(vrf, pro))
    except Exception as e:
        output.exception(e)

def arp_get_all(obj, vrf, proto=''):
    try:
        result = dict()
        result[vrf] = dict()

        proto_l = list()
        if proto:
            proto_l.append(proto)
            result[vrf][proto] = list()
        else:
            proto_l.append('v4')
            proto_l.append('v6')
            result[vrf]['v4'] = list()
            result[vrf]['v6'] = list()

        l3_cfg = obj.filter('flow_l3_cfg')
        if len(l3_cfg):
            arp = l3_cfg[0].filter('arp', vrf)
            if len(arp):
                for pro in proto_l:
                    v = arp[0].filter(pro)
                    for r in v:
                        key = dict()
                        for x in r.children:
                            key[x.name] = x.value

                        result[vrf][pro].append(key)

        return result
    except Exception as e:
        output.exception(e)

################ arp cfg end  ########################################


################ switch start ########################################
def flow_switch_set(obj, **kw):
    try:
        l3_cfg = obj.filter('flow_l3_cfg')
        if len(l3_cfg):
            switch = l3_cfg[0].filter('switch')
            if len(switch):
                for k, v in kw.items():
                    i = switch[0].filter('', k)
                    if len(i):
                        i[0].value = v
                        output.info('set flow-switch {} {}'.format(k, v))
                    else:
                        key = Key(k, v)
                        switch[0].add(key)
                        output.info('set flow-switch {} {}'.format(k, v))
    except Exception as e:
        output.exception(e)

def flow_switch_get(obj):
    try:
        result = dict()
        l3_cfg = obj.filter('flow_l3_cfg')
        if len(l3_cfg):
            switch = l3_cfg[0].filter('switch')
            if len(switch):
                for i in switch[0].children:
                    result[i.name] = i.value
        return result
    except Exception as e:
        output.exception(e)
################ switch endi  ########################################



