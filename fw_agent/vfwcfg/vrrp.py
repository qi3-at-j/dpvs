from .vfw_base import Key
from .log_output import output

def vrrp_cfg_set(obj, **kw):
    try:
        vrrp_cfg = obj.filter('vrrp_cfg')
        if len(vrrp_cfg):
            for k, v in kw.items():
                if not v:
                    continue

                vv = vrrp_cfg[0].filter('', k)
                if len(vv):
                    if vv[0].value != v:
                        output.info('vrrp set {} {} -> {}'.format(k, vv[0].value, v))
                        vv[0].value = v 
                else:
                    item = Key(k, v)
                    vrrp_cfg[0].add(item)
                    output.info('vrrp set {} none -> {}'.format(k, v))

        return ''
    except Exception as e:
        output.exception(e)

def vrrp_cfg_get(obj):
    try:
        result = dict()
        vrrp_cfg = obj.filter('vrrp_cfg')
        if len(vrrp_cfg):
            for i in vrrp_cfg[0].children:
                if i.name == 'vrrp_virtual_ipaddress':
                    result['vip'] = i.value
                    continue

                if i.name == 'vrrp_virtual_ipv6':
                    result['vip6'] = i.value
                    continue

                if i.name == 'vrrp_unicast_peer':
                    result['peer'] = i.value
                    continue

                if i.name == 'vrrp_enable':
                    result['status'] = i.value
                    continue

                if i.name == 'vrrp_interface':
                    result['interface'] = i.value
                    continue

                if i.name == 'vrrp_virtual_router_id':
                    result['vrid'] = i.value
                    continue

                result[i.name] = i.value

        return result
    except Exception as e:
        output.exception(e)
