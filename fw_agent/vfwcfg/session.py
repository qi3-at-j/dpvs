from .log_output import output

def session_app_aging_modify(obj, name, value):
    try:
        ss = obj.filter('session_cfg')
        if len(ss):
            v = ss[0].filter('app_aging_time')
            if len(v):
                vv = v[0].filter('', name)
                if len(vv):
                    output.info("Session app_aging: {0} {1} -> {2}".format(name, vv[0].value, value))
                    vv[0].value = value 
    except Exception as e:
        output.exception(e)

def session_state_aging_modify(obj, name, value):
    try:
        ss = obj.filter('session_cfg')
        if len(ss):
            v = ss[0].filter('state_aging_time')
            if len(v):
                vv = v[0].filter('', name)
                if len(vv):
                    output.info("Session state_aging: {0} {1} -> {2}".format(name, vv[0].value, value))
                    vv[0].value = value 
    except Exception as e:
        output.exception(e)

def session_global_modify(obj, name, value):
    try:
        ss = obj.filter('session_cfg')
        if len(ss):
            v = ss[0].filter('', name)
            if len(v):
                output.info("Session global: {0} {1} -> {2}".format(name, v[0].value, value))
                v[0].value = value 
    except Exception as e:
        output.exception(e)

class session_get_cfg():
    def __init__(self, obj):
        try:
            ss = obj.filter('session_cfg')
            if len(ss):
                v = ss[0].filter('app_aging_time')
                if len(v):
                    vv = v[0].filter('', 'dns')
                    if len(vv):
                        self.dns = vv[0].value
                    vv = v[0].filter('', 'ftp')
                    if len(vv):
                        self.ftp = vv[0].value
                    vv = v[0].filter('', 'sip')
                    if len(vv):
                        self.sip = vv[0].value
                    vv = v[0].filter('', 'tftp')
                    if len(vv):
                        self.tftp = vv[0].value
                    vv = v[0].filter('', 'ftp_data')
                    if len(vv):
                        self.ftp_data = vv[0].value
                    vv = v[0].filter('', 'https')
                    if len(vv):
                        self.https = vv[0].value
                    vv = v[0].filter('', 'others')
                    if len(vv):
                        self.others = vv[0].value

                v = ss[0].filter('state_aging_time')
                if len(v):
                    vv = v[0].filter('', 'fin')
                    if len(vv):
                        self.fin = vv[0].value
                    vv = v[0].filter('', 'icmp_replay')
                    if len(vv):
                        self.icmp_replay = vv[0].value
                    vv = v[0].filter('', 'icmp_request')
                    if len(vv):
                        self.icmp_request = vv[0].value
                    vv = v[0].filter('', 'rawip_open')
                    if len(vv):
                        self.rawip_open = vv[0].value
                    vv = v[0].filter('', 'rawip_ready')
                    if len(vv):
                        self.rawip_ready = vv[0].value
                    vv = v[0].filter('', 'syn')
                    if len(vv):
                        self.syn = vv[0].value
                    vv = v[0].filter('', 'tcp_close')
                    if len(vv):
                        self.tcp_close = vv[0].value
                    vv = v[0].filter('', 'tcp_est')
                    if len(vv):
                        self.tcp_est = vv[0].value
                    vv = v[0].filter('', 'tcp_time_wait')
                    if len(vv):
                        self.tcp_time_wait = vv[0].value
                    vv = v[0].filter('', 'udp_open')
                    if len(vv):
                        self.udp_open = vv[0].value
                    vv = v[0].filter('', 'udp_ready')
                    if len(vv):
                        self.udp_ready = vv[0].value

                v = ss[0].filter('', 'session_log')
                if len(v):
                    self.session_log = v[0].value

                v = ss[0].filter('', 'session_statistics')
                if len(v):
                    self.session_statistics = v[0].value
        except Exception as e:
            output.exception(e)
