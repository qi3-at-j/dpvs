from .vfw_base import Block 
from .vfw_base import Key
from .log_output import output

user_ids = [None] * 64
fw_type = True

def uid_get(obj, uid='', act='del'):
    try:
        if not uid:
            return ''

        if uid.isdigit() and len(uid) < 3:
            return uid

        if uid in user_ids:
            return str(user_ids.index(uid))
        else:
            if act == 'del':
                return ''

        if user_ids.count(None):
            i = user_ids.index(None)
            user_ids.pop(i)
            user_ids.insert(i, uid)

            id_maps = obj.filter('userid_maps')
            if len(id_maps):
                k = Key('map', uid+'-'+str(i))
                id_maps[0].add(k)

            return str(i)
        else:
            user_ids.append(uid)
            i = user_ids.index(uid)

            id_maps = obj.filter('userid_maps')
            if len(id_maps):
                k = Key('map', uid+'-'+str(i))
                id_maps[0].add(k)

            output.warning('The maximum specification limit of vFW has been exceeded. uid {}.'.format(uid))

            return str(i)

    except Exception as e:
        output.exception(e)

def get_fw_type():
    return fw_type

def fw_init(obj):
    try:
        conf = obj.filter('fw_global_conf')
        if len(conf):
            b = conf[0].filter('', 'fw_type')
            if len(b):
                # external internal
                global fw_type
                if b[0].value == 'external':
                    # ext boder
                    fw_type = True

                if b[0].value == 'internal':
                    # vpc boder
                    fw_type = False

        # id:0 Reserved
        user_ids.pop(0)
        user_ids.insert(0, 'Reserved')

        id_maps = obj.filter('userid_maps')
        for k in id_maps[0].children:
            xx = k.value.rsplit('-', 1)
            if len(xx) != 2:
                output.warning('The user ID, {}, is invalid.'.format(k.value))
                continue
            if xx[0] not in user_ids:
                user_ids.pop(int(xx[1]))
                user_ids.insert(int(xx[1]), xx[0])
            else:
                output.warning('The user ID, {}, already exists.'.format(xx[0]))
    except Exception as e:
        output.exception(e)

def vrf_add(obj, vrf):
    try:
        l2_cfg = obj.filter('flow_l2_cfg')
        if len(l2_cfg):
            limit = Block('rate_limit', vrf)
            l2_cfg[0].add(limit)

        l3_cfg = obj.filter('flow_l3_cfg')
        if len(l3_cfg):
            arp = Block('arp', vrf)
            route = Block('route', vrf)
            vrf_bind = Block('vrf_bind', vrf)

            l3_cfg[0].add(arp)
            l3_cfg[0].add(route)
            l3_cfg[0].add(vrf_bind)

        v = Block('vrf_index', vrf)

        n = Block('subnet')
        v.add(n)

        n = Block('security_policy_in')

        v4 = Block('ipv4')
        n.add(v4)

        v6 = Block('ipv6')
        n.add(v6)

        v.add(n)

        n = Block('security_policy_out')

        v4 = Block('ipv4')
        n.add(v4)

        v6 = Block('ipv6')
        n.add(v6)

        v.add(n)

        n = Block('aspf_policy')
        k = Key('detect', 'ftp')
        n.add(k)
        k = Key('tcp_syn_check', 'disable')
        n.add(k)
        v.add(n)

        n = Block('dpi_cfg')
        v.add(n)

        n = Block('ips_policy')
        v.add(n)

        obj.add(v)
        output.info('Add vrf {}.'.format(vrf))

    except Exception as e:
        output.exception(e)

def vrf_del(obj, vrf):
    try:
        id_maps = obj.filter('userid_maps')
        for k in id_maps[0].children:
            xx = k.value.rsplit('-', 1)
            if len(xx) != 2:
                continue

            if xx[1] == vrf:
                i = user_ids.index(xx[0])
                user_ids.pop(i)
                user_ids.insert(i, None)
                id_maps[0].remove(k)
                break

        l2_cfg = obj.filter('flow_l2_cfg')
        if len(l2_cfg):
            limit = l2_cfg[0].filter('rate_limit', vrf)
            if len(limit):
                l2_cfg[0].remove(limit[0])

        l3_cfg = obj.filter('flow_l3_cfg')
        if len(l3_cfg):
            arp = l3_cfg[0].filter('arp', vrf)
            if len(arp):
                l3_cfg[0].remove(arp[0])

            route = l3_cfg[0].filter('route', vrf)
            if len(route):
                l3_cfg[0].remove(route[0])

            vrf_bind = l3_cfg[0].filter('vrf_bind', vrf)
            if len(vrf_bind):
                l3_cfg[0].remove(vrf_bind[0])


        s = obj.filter('vrf_index', vrf)
        if len(s):
            obj.remove(s[0])
            output.info('Del vrf {}.'.format(vrf))
    except Exception as e:
        output.exception(e)

def vrf_is_exist(obj, vrf):
    try:
        s = obj.filter('vrf_index', vrf)
        if len(s):
            return True
        return False
    except Exception as e:
        output.exception(e)

