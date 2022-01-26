#!/usr/bin/env python3
import os
import sys
import re
import time
import signal
import socket
import signal
import copy
import json
import copy

from flask import Flask, Blueprint, jsonify
from flask import request
from flask_restful import Resource, Api, reqparse
from subprocess import Popen
from subprocess import PIPE as subprocPIPE
from vfwcfg import output
import vfwcfg

src_file = './etc/dpvs.conf'
dst_file = './etc/dpvs.conf'
serverAddr = '/var/run/tyflow_cmd_batch'
ips_rule = './etc/ips_rules'

dict_ips_rules = dict()

list_ips_base_rules = list()
dict_ips_base_method = dict()
dict_ips_base_target = dict()

list_ips_vpatch_rules = list()
dict_ips_vpatch_method = dict()
dict_ips_vpatch_target = dict()

conf_obj = None
conn_fd = None

# config log
#DEBUG = False
#logging.basicConfig(format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s', 
#        level=logging.DEBUG if DEBUG else logging.INFO,
#        filename='/var/log/vfw.log', filemode='w')

#def vfw_popen(cmd):
#    pro = Popen(cmd, stdout=subprocPIPE, stderr=subprocPIPE, shell=True)
#    stdout, stderr = pro.communicate()
#    output_string = stdout.decode('utf-8')
#    return output_string

def vfw_connect():
    try:
        client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client_sock.connect(serverAddr)
        #output.info('Successfully connected to the server.')
        return client_sock
    except Exception as e:
        output.exception(e)

def vfw_send(msgs):
    try:
        #global conn_fd
        #if conn_fd is None:
        #    conn_fd = vfw_connect()

        #conn_fd = vfw_connect()

        for msg in msgs:
            conn_fd = vfw_connect()
            # output.info(msg)
            # print('fw-agent: {}'.format(msg))
            msg = 'CMDB' + msg + '\n'
            conn_fd.send(msg.encode())
            conn_fd.close()


        #conn_fd.close()
    except Exception as e:
        output.exception(e)

def ips_init():
    ips_rule_f = open(ips_rule, 'r')
    ips_rule_json = ips_rule_f.read()
    ips_rule_dict_s = json.loads(ips_rule_json)
    ips_rule_dict = eval(ips_rule_dict_s)
    ips_rule_f.close()

    for rule_id in ips_rule_dict.keys():
        dict_ips_rules[rule_id] = copy.deepcopy(ips_rule_dict[rule_id])

        gid = dict_ips_rules[rule_id].get('gid')

        if gid == 4:
            list_ips_vpatch_rules.append(rule_id)
            method_list = dict_ips_rules[rule_id]['method']
            if len(method_list) > 1:
                print(rule_id)
            for method in method_list:
                if method in dict_ips_vpatch_method.keys():
                    dict_ips_vpatch_method[method].append(rule_id)
                else:
                    dict_ips_vpatch_method[method] = list()
                    dict_ips_vpatch_method[method].append(rule_id)

            target_list = dict_ips_rules[rule_id]['target']
            if len(target_list) > 1:
                print(rule_id)
            for target in target_list:
                if target in dict_ips_vpatch_target.keys():
                    dict_ips_vpatch_target[target].append(rule_id)
                else:
                    dict_ips_vpatch_target[target] = list()
                    dict_ips_vpatch_target[target].append(rule_id)
        else:
            list_ips_base_rules.append(rule_id)
            method_list = dict_ips_rules[rule_id]['method']
            if len(method_list) > 1:
                print(rule_id)
            for method in method_list:
                if method in dict_ips_base_method.keys():
                    dict_ips_base_method[method].append(rule_id)
                else:
                    dict_ips_base_method[method] = list()
                    dict_ips_base_method[method].append(rule_id)

            target_list = dict_ips_rules[rule_id]['target']
            if len(target_list) > 1:
                print(rule_id)
            for target in target_list:
                if target in dict_ips_base_target.keys():
                    dict_ips_base_target[target].append(rule_id)
                else:
                    dict_ips_base_target[target] = list()
                    dict_ips_base_target[target].append(rule_id)

# fw cfg
VrfBp = Blueprint('VrfBp', __name__)
SessionCfgBp  = Blueprint('SessionCfgBp', __name__)
SecPolicySubnetBp = Blueprint('SecPolicySubnetBp', __name__)
SecPolicyInCfgBp = Blueprint('SecPolicyInCfgBp', __name__)
SecPolicyOutCfgBp = Blueprint('SecPolicyOutCfgBp', __name__)
AspfPolicyCfgBp  = Blueprint('AspfPolicyCfgBp', __name__)
SecPolicyInOrderBp = Blueprint('SecPolicyInOrderBp', __name__)
SecPolicyOutOrderBp = Blueprint('SecPolicyOutOrderBp', __name__)
IpsCfgBp  = Blueprint('IpsCfgBp', __name__)
IpsRuleCfgBp  = Blueprint('IpsRuleCfgBp', __name__)

# l2 cfg
VlanPortCfgBp  = Blueprint('VlanPortCfgBp', __name__)
PortIPCfgBp    = Blueprint('PortIPCfgBp', __name__)

# l3 cfg
RouteCfgBp   = Blueprint('RouteCfgBp', __name__)
VxlanCfgBp   = Blueprint('VxlanCfgBp', __name__)
ArpCfgBp     = Blueprint('ArpCfgBp', __name__)
VrfBindCfgBp = Blueprint('VrfBindCfgBp', __name__)
FlowSwitchCfgBp = Blueprint('FlowSwitchCfgBp', __name__)
RateLimitCfgBp = Blueprint('RateLimitCfgBp', __name__)
VrrpCfgBp = Blueprint('VrrpCfgBp', __name__)

VrfCfgApi = Api(VrfBp)
SessionCfgApi = Api(SessionCfgBp)
SecPolicySubnetCfgApi = Api(SecPolicySubnetBp)
SecPolicyInCfgApi = Api(SecPolicyInCfgBp)
SecPolicyOutCfgApi = Api(SecPolicyOutCfgBp)
AspfPolicyCfgApi = Api(AspfPolicyCfgBp)
SecPolicyInOrderApi = Api(SecPolicyInOrderBp)
SecPolicyOutOrderApi = Api(SecPolicyOutOrderBp)
IpsCfgApi = Api(IpsCfgBp)
IpsRuleCfgApi = Api(IpsRuleCfgBp)

VlanPortCfgApi = Api(VlanPortCfgBp)
PortIPCfgApi   = Api(PortIPCfgBp)

RouteCfgApi = Api(RouteCfgBp)
VxlanCfgApi = Api(VxlanCfgBp)
ArpCfgApi   = Api(ArpCfgBp)
VrfBindCfgApi = Api(VrfBindCfgBp)
FlowSwitchCfgApi = Api(FlowSwitchCfgBp)
RateLimitCfgApi = Api(RateLimitCfgBp)
VrrpCfgApi = Api(VrrpCfgBp)

app = Flask(__name__)
app.register_blueprint(VrfBp)
app.register_blueprint(SessionCfgBp)
app.register_blueprint(SecPolicySubnetBp)
app.register_blueprint(SecPolicyInCfgBp)
app.register_blueprint(SecPolicyOutCfgBp)
app.register_blueprint(AspfPolicyCfgBp)
app.register_blueprint(SecPolicyInOrderBp)
app.register_blueprint(SecPolicyOutOrderBp)
app.register_blueprint(IpsCfgBp)
app.register_blueprint(IpsRuleCfgBp)

app.register_blueprint(VlanPortCfgBp)
app.register_blueprint(PortIPCfgBp)
app.register_blueprint(RouteCfgBp)
app.register_blueprint(VxlanCfgBp)
app.register_blueprint(ArpCfgBp)
app.register_blueprint(VrfBindCfgBp)
app.register_blueprint(FlowSwitchCfgBp)
app.register_blueprint(RateLimitCfgBp)
app.register_blueprint(VrrpCfgBp)

class SessionCfg(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(trim = True, bundle_errors = True)

        # app_aging_time
        self.reqparse.add_argument('dns', type = int, location = 'json')
        self.reqparse.add_argument('ftp', type = int, location = 'json')
        self.reqparse.add_argument('sip', type = int, location = 'json')
        self.reqparse.add_argument('tftp', type = int, location = 'json')
        self.reqparse.add_argument('ftp_data', type = int, location = 'json')
        self.reqparse.add_argument('https', type = int, location = 'json')
        self.reqparse.add_argument('others', type = int, location = 'json')

        # state_aging_time
        self.reqparse.add_argument('fin', type = int, location = 'json')
        self.reqparse.add_argument('icmp_replay', type = int, location = 'json')
        self.reqparse.add_argument('icmp_request', type = int, location = 'json')
        self.reqparse.add_argument('rawip_open', type = int, location = 'json')
        self.reqparse.add_argument('rawip_ready', type = int, location = 'json')
        self.reqparse.add_argument('syn', type = int, location = 'json')
        self.reqparse.add_argument('tcp_close', type = int, location = 'json')
        self.reqparse.add_argument('tcp_est', type = int, location = 'json')
        self.reqparse.add_argument('tcp_time_wait', type = int, location = 'json')
        self.reqparse.add_argument('udp_open', type = int, location = 'json')
        self.reqparse.add_argument('udp_ready', type = int, location = 'json')

        # global config
        self.reqparse.add_argument('session_log', type = str, default = '', location = 'json')
        self.reqparse.add_argument('session_statistics', type = str, default = '', location = 'json')

        # app_aging_time
        self.args = self.reqparse.parse_args(strict = True)
        self.dns = self.args['dns']
        self.ftp = self.args['ftp']
        self.sip = self.args['sip']
        self.tftp  = self.args['tftp']
        self.ftp_data = self.args['ftp_data']  
        self.https = self.args['https']
        self.others = self.args['others']

        # state_aging_time
        self.fin = self.args['fin']
        self.icmp_replay = self.args['icmp_replay']
        self.icmp_request = self.args['icmp_request']
        self.rawip_open = self.args['rawip_open']
        self.rawip_ready = self.args['rawip_ready']
        self.syn = self.args['syn']
        self.tcp_close = self.args['tcp_close']
        self.tcp_est = self.args['tcp_est']
        self.tcp_time_wait = self.args['tcp_time_wait']
        self.udp_open = self.args['udp_open']
        self.udp_ready = self.args['udp_ready']

        # global config
        self.session_log = self.args['session_log'].strip()
        self.session_statistics = self.args['session_statistics'].strip()
        self.msgs = list()

    def get(self):

        global conf_obj
        if conf_obj:
            s = conf_obj
        else:
            conf_obj = vfwcfg.loadf(src_file)
            s = conf_obj

        cfg = vfwcfg.session_get_cfg(s)
        result = {
            'app_aging_time': {
                'dns': cfg.dns,
                'ftp': cfg.ftp,
                'sip': cfg.sip,
                'tftp': cfg.tftp,
                'ftp_data': cfg.ftp_data,
                'https': cfg.https,
                'others': cfg.others
            },
            'state_aging_time': {
                'fin': cfg.fin,
                'icmp_replay': cfg.icmp_replay,
                'icmp_request': cfg.icmp_request, 
                'rawip_open': cfg.rawip_open,
                'rawip_ready': cfg.rawip_ready,
                'syn': cfg.syn,
                'tcp_close': cfg.tcp_close,
                'tcp_est': cfg.tcp_est,
                'tcp_time_wait': cfg.tcp_time_wait,
                'udp_open': cfg.udp_open,
                'udp_ready': cfg.udp_ready
            },
            'session_log': cfg.session_log,
            'session_statistics': cfg.session_statistics
        }

        return jsonify(result)

    # modify | merge
    def patch(self):
        global conf_obj
        if conf_obj:
            s = conf_obj
        else:
            conf_obj = vfwcfg.loadf(src_file)
            s = conf_obj

        if self.fin and isinstance(self.fin, int):
            vfwcfg.session_state_aging_modify(s, 'fin', self.fin)
            self.msgs.append('set session aging-time state fin {}'.format(self.fin))
        if self.icmp_replay and isinstance(self.icmp_replay, int):
            vfwcfg.session_state_aging_modify(s, 'icmp_replay', self.icmp_replay)
            self.msgs.append('set session aging-time state icmp-reply {}'.format(self.icmp_replay))
        if self.icmp_request and isinstance(self.icmp_request, int):
            vfwcfg.session_state_aging_modify(s, 'icmp_request', self.icmp_request)
            self.msgs.append('set session aging-time state icmp-request {}'.format(self.icmp_request))
        if self.rawip_open and isinstance(self.rawip_open, int):
            vfwcfg.session_state_aging_modify(s, 'rawip_open', self.rawip_open)
            self.msgs.append('set session aging-time state rawip-open {}'.format(self.rawip_open))
        if self.rawip_ready and isinstance(self.rawip_ready, int):
            vfwcfg.session_state_aging_modify(s, 'rawip_ready', self.rawip_ready)
            self.msgs.append('set session aging-time state rawip-ready {}'.format(self.rawip_ready))
        if self.syn and isinstance(self.syn, int):
            vfwcfg.session_state_aging_modify(s, 'syn', self.syn)
            self.msgs.append('set session aging-time state syn {}'.format(self.syn))
        if self.tcp_close and isinstance(self.tcp_close, int):
            vfwcfg.session_state_aging_modify(s, 'tcp_close', self.tcp_close)
            self.msgs.append('set session aging-time state tcp-close {}'.format(self.tcp_close))
        if self.tcp_est and isinstance(self.tcp_est, int):
            vfwcfg.session_state_aging_modify(s, 'tcp_est', self.tcp_est)
            self.msgs.append('set session aging-time state tcp-est {}'.format(self.tcp_est))
        if self.tcp_time_wait and isinstance(self.tcp_time_wait, int):
            vfwcfg.session_state_aging_modify(s, 'tcp_time_wait', self.tcp_time_wait)
            self.msgs.append('set session aging-time state tcp-time-wait {}'.format(self.tcp_time_wait))
        if self.udp_open and isinstance(self.udp_open, int):
            vfwcfg.session_state_aging_modify(s, 'udp_open', self.udp_open)
            self.msgs.append('set session aging-time state udp-open {}'.format(self.udp_open))
        if self.udp_ready and isinstance(self.udp_ready, int):
            vfwcfg.session_state_aging_modify(s, 'udp_ready', self.udp_ready)
            self.msgs.append('set session aging-time state udp-ready {}'.format(self.udp_ready))

        if self.dns and isinstance(self.dns, int):
            vfwcfg.session_app_aging_modify(s, 'dns', self.dns)
            self.msgs.append('set session dns {}'.format(self.dns))
        if self.ftp and isinstance(self.ftp, int):
            vfwcfg.session_app_aging_modify(s, 'ftp', self.ftp)
            self.msgs.append('set session ftp {}'.format(self.ftp))
        if self.sip and isinstance(self.sip, int):
            vfwcfg.session_app_aging_modify(s, 'sip', self.sip)
            self.msgs.append('set session sip {}'.format(self.sip))
        if self.tftp and isinstance(self.tftp, int):
            vfwcfg.session_app_aging_modify(s, 'tftp', self.tftp)
            self.msgs.append('set session tftp {}'.format(self.tftp))
        if self.ftp_data and isinstance(self.ftp_data, int):
            vfwcfg.session_app_aging_modify(s, 'ftp_data', self.ftp_data)
            self.msgs.append('set session ftp_data {}'.format(self.ftp_data))
        if self.https and isinstance(self.https, int):
            vfwcfg.session_app_aging_modify(s, 'https', self.https)
            self.msgs.append('set session https {}'.format(self.https))
        if self.others and isinstance(self.others, int):
            vfwcfg.session_app_aging_modify(s, 'others', self.others)
            self.msgs.append('set session others {}'.format(self.others))

        if self.session_log:
            v = self.session_log.lower()
            if v == 'disable' or v == 'enable':
                vfwcfg.session_global_modify(s, 'session_log', v)
                if v == 'enable':
                    self.msgs.append('set session log enable')
                if v == 'disable':
                    self.msgs.append('unset session log enable')

        if self.session_statistics:
            v = self.session_statistics.lower()
            if v == 'disable' or v == 'enable':
                vfwcfg.session_global_modify(s, 'session_statistics', v)
                if v == 'enable':
                    self.msgs.append('set session statistics enable')
                if v == 'disable':
                    self.msgs.append('unset session statistics enable')

        vfwcfg.dumpf(s, dst_file)

        vfw_send(self.msgs)

        self.return_string = 'OK'
        response = SessionCfgApi.make_response(self.return_string, 200)
        return jsonify(status = self.return_string)

class AspfPolicyCfg(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(trim = True, bundle_errors = True)
        self.reqparse.add_argument('uid',     type = str, location = 'json')
        self.reqparse.add_argument('detect',  type = str, default = '', location = 'json')
        self.reqparse.add_argument('action',  type = str, default = '', location = 'json')
        self.reqparse.add_argument('tcp_syn_check',  type = str, default = '', location = 'json')

        self.args = self.reqparse.parse_args(strict = True)
        self.vrf     = self.args['uid'].strip()
        self.detect  = self.args['detect'].strip()
        self.action  = self.args['action'].strip()
        self.tcp_syn_check = self.args['tcp_syn_check'].strip()
        self.msgs    = list()

    def get(self):

        global conf_obj
        if conf_obj:
            s = conf_obj
        else:
            conf_obj = vfwcfg.loadf(src_file)
            s = conf_obj

        # convert uuid to id
        self.vrf = vfwcfg.uid_get(s, self.vrf)

        if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
            self.return_string = 'Not Found'
            response = AspfPolicyCfgApi.make_response(self.return_string, 404)
            return response

        cfg = vfwcfg.aspf_policy_id_get(s, self.vrf)

        result = ''
        if cfg:
            result = {
                self.vrf: {
                    'detect': cfg.detect,
                    'tcp_syn_check': cfg.tcp_syn_check
                },
            }

        self.return_string = 'OK'
        response = AspfPolicyCfgApi.make_response(self.return_string, 200)
        return jsonify(result)

    # modify | merge
    def patch(self):
        global conf_obj
        if conf_obj:
            s = conf_obj
        else:
            conf_obj = vfwcfg.loadf(src_file)
            s = conf_obj

        # convert uuid to id
        self.vrf = vfwcfg.uid_get(s, self.vrf)

        if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
            self.return_string = 'Bad Request'
            response = AspfPolicyCfgApi.make_response(self.return_string, 400)
            return response

        if self.action == 'insert' and self.detect:
            for detect in self.detect.split(','):
                vfwcfg.aspf_policy_detect_insert(s, self.vrf, detect.strip())
                self.msgs.append('set vrf {} aspf-policy detect {}'.format(self.vrf, detect.strip()))

        if self.action == 'remove' and self.detect:
            for detect in self.detect.split(','):
                vfwcfg.aspf_policy_detect_remove(s, self.vrf, detect.strip())
                self.msgs.append('unset vrf {} aspf-policy detect {}'.format(self.vrf, detect.strip()))

        if self.tcp_syn_check:
            v = self.tcp_syn_check.lower()
            if v == 'disable' or v == 'enable':
                vfwcfg.aspf_policy_modify(s, self.vrf, 'tcp_syn_check', v)
                self.msgs.append('set vrf {} aspf-policy tcp-syn-check {}'.format(self.vrf, v))

        vfwcfg.dumpf(s, dst_file)

        vfw_send(self.msgs)

        self.return_string = 'OK'
        response = AspfPolicyCfgApi.make_response(self.return_string, 200)
        return jsonify(status = self.return_string)

class SecPolicySubnetCfg(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(trim = True, bundle_errors = True)
        self.reqparse.add_argument('uid',      type = str, default = '', location = 'json', required=True)
        self.reqparse.add_argument('ip_proto', type = str, default = '', location = 'json')
        self.reqparse.add_argument('ip',       type = str, default = '', location = 'json')

        self.args      = self.reqparse.parse_args(strict = True)
        self.vrf       = self.args['uid'].strip()
        self.ip_proto  = self.args['ip_proto'].strip()
        self.ip        = self.args['ip'].strip()
        self.msgs      = list()

    def post(self):
        global conf_obj
        if conf_obj:
            s = conf_obj
        else:
            conf_obj = vfwcfg.loadf(src_file)
            s = conf_obj

        result = dict()
        result['code'] = '200'
        result['msg'] = 'OK'
        result['data'] = None

        url = request.path.strip('/ ').rsplit('/', 1)
        if url[-1] == 'query':
            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
                #self.return_string = 'Not Found'
                #response = SecPolicySubnetCfgApi.make_response(self.return_string, 404)
                #return response
                result['code'] = '404'
                result['msg'] = 'Not Found'
                return jsonify(result)

            result['data'] = vfwcfg.sec_policy_subnet_get(s, self.vrf, self.ip_proto)
            return jsonify(result)

        if url[-1] == 'add':
            # cmd format
            # set secpolicy ip   vrf    1 vpc-subnet-ip   1.1.1.1
            # set secpolicy ip   tenant 1 ext-subnet-ip   1.1.1.1
            # set secpolicy ipv6 vrf    1 vpc-subnet-ipv6 1::1
            # set secpolicy ipv6 tenant 1 ext-subnet-ipv6 1::1

            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
                #self.return_string = 'Bad Request'
                #response = SecPolicySubnetCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if self.ip_proto != 'v4' and self.ip_proto != 'v6':
                #self.return_string = 'Bad Request'
                #response = SecPolicySubnetCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if not self.ip:
                #self.return_string = 'Bad Request'
                #response = SecPolicySubnetCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            vfwcfg.sec_policy_subnet_add(s, self.vrf, self.ip_proto, self.ip)
            vfwcfg.dumpf(s, dst_file)

            msg = 'set secpolicy'

            if self.ip_proto == 'v4':
                msg += ' ip'

                # strip spaces
                ip_list = self.ip.split(',')
                for i in range(len(ip_list)):
                    ip_list[i] = ip_list[i].strip()

                ip = ','.join(ip_list)

                if vfwcfg.get_fw_type():
                    msg += ' tenant {} ext-subnet-ip {}'.format(self.vrf, ip)
                else:
                    msg += ' vrf {} vpn-subnet-ip {}'.format(self.vrf, ip)

            if self.ip_proto == 'v6':
                msg += ' ipv6'

                # strip spaces
                ip_list = self.ip.split(',')
                for i in range(len(ip_list)):
                    ip_list[i] = ip_list[i].strip()

                ip = ','.join(ip_list)

                if vfwcfg.get_fw_type():
                    msg += ' tenant {} ext-subnet-ip6 {}'.format(self.vrf, ip)
                else:
                    msg += ' vrf {} vpn-subnet-ip6 {}'.format(self.vrf, ip)

            # end
            self.msgs.append(msg)

            vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = SecPolicySubnetCfgApi.make_response(self.return_string, 200)
            #return jsonify(status = self.return_string)
            return jsonify(result)

        # def delete(self):
        if url[-1] == 'delete':
            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)

            # cmd format
            # unset secpolicy ip   vrf    1 vpc-subnet-ip   1.1.1.1
            # unset secpolicy ip   tenant 1 ext-subnet-ip   1.1.1.1
            # unset secpolicy ipv6 vrf    1 vpc-subnet-ipv6 1::1
            # unset secpolicy ipv6 tenant 1 ext-subnet-ipv6 1::1

            if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
                #self.return_string = 'Bad Request'
                #response = SecPolicySubnetCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if self.ip_proto != 'v4' and self.ip_proto != 'v6':
                #self.return_string = 'Bad Request'
                #response = SecPolicySubnetCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if not self.ip:
                #self.return_string = 'Bad Request'
                #response = SecPolicySubnetCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            vfwcfg.sec_policy_subnet_del(s, self.vrf, self.ip_proto, self.ip)
            vfwcfg.dumpf(s, dst_file)

            msg = 'unset secpolicy'

            if self.ip_proto == 'v4':
                msg += ' ip'

                # strip spaces
                ip_list = self.ip.split(',')
                for i in range(len(ip_list)):
                    ip_list[i] = ip_list[i].strip()

                ip = ','.join(ip_list)

                if vfwcfg.get_fw_type():
                    msg += ' tenant {} ext-subnet-ip {}'.format(self.vrf, ip)
                else:
                    msg += ' vrf {} vpn-subnet-ip {}'.format(self.vrf, ip)

            if self.ip_proto == 'v6':
                msg += ' ipv6'

                # strip spaces
                ip_list = self.ip.split(',')
                for i in range(len(ip_list)):
                    ip_list[i] = ip_list[i].strip()

                ip = ','.join(ip_list)

                if vfwcfg.get_fw_type():
                    msg += ' tenant {} ext-subnet-ip6 {}'.format(self.vrf, ip)
                else:
                    msg += ' vrf {} vpn-subnet-ip6 {}'.format(self.vrf, ip)

            # end
            self.msgs.append(msg)

            vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = SecPolicySubnetCfgApi.make_response(self.return_string, 200)
            #return jsonify(status = self.return_string)
            return jsonify(result)

class SecPolicyInCfg(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(trim = True, bundle_errors = True)
        self.reqparse.add_argument('uid',        type = str, default = '', location = 'json', required=True)
        self.reqparse.add_argument('ip_proto',   type = str, default = '', location = 'json')
        self.reqparse.add_argument('rule_id',    type = str, default = '', location = 'json')
        self.reqparse.add_argument('desc',       type = str, default = '', location = 'json')
        self.reqparse.add_argument('action',     type = str, default = '', location = 'json')
        self.reqparse.add_argument('dst_ip',     type = str, default = '', location = 'json')
        self.reqparse.add_argument('dst_ip6',    type = str, default = '', location = 'json')
        self.reqparse.add_argument('src_ip',     type = str, default = '', location = 'json')
        self.reqparse.add_argument('src_ip6',    type = str, default = '', location = 'json')
        self.reqparse.add_argument('service',    type = str, default = '', location = 'json')
        self.reqparse.add_argument('dst_port',   type = str, default = '', location = 'json')
        self.reqparse.add_argument('src_port',   type = str, default = '', location = 'json')
        self.reqparse.add_argument('icmp_type',  type = str, default = '', location = 'json')
        self.reqparse.add_argument('icmp_code',  type = str, default = '', location = 'json')
        self.reqparse.add_argument('app',        type = str, default = '', location = 'json')
        self.reqparse.add_argument('status',     type = str, default = '', location = 'json')
        self.reqparse.add_argument('statistics', type = str, default = '', location = 'json')

        self.args       = self.reqparse.parse_args(strict = True)
        self.vrf        = self.args['uid'].strip()
        self.ip_proto   = self.args['ip_proto'].strip()
        self.rule_id    = self.args['rule_id'].strip()
        self.desc       = self.args['desc']
        self.action     = self.args['action'].strip()
        self.dst_ip     = self.args['dst_ip'].strip()
        self.dst_ip6    = self.args['dst_ip6'].strip()  
        self.src_ip     = self.args['src_ip'].strip()
        self.src_ip6    = self.args['src_ip6'].strip()
        self.service    = self.args['service'].strip()
        self.dst_port   = self.args['dst_port'].strip()
        self.src_port   = self.args['src_port'].strip()
        self.icmp_type  = self.args['icmp_type'].strip()
        self.icmp_code  = self.args['icmp_code'].strip()
        self.app        = self.args['app'].strip()
        self.status     = self.args['status'].strip()
        self.statistics = self.args['statistics'].strip()
        self.msgs       = list()

    def post(self):

        # cmd format
        # set secpolicy ip vrf 1 in2out-rule 1 action drop src-ip 1.1.1.1 dst-ip 1.1.1.1 service tcp src-port 1 to 2 dst-port 4 to 5 status enable statistics enable
        # set secpolicy ip vrf 1 in2out-rule 1 action drop src-ip 1.1.1.1 dst-ip 1.1.1.1 service udp src-port 1 to 2 dst-port 4 to 5 status enable statistics enable
        # set secpolicy ip vrf 4 in2out-rule 1 action drop src-ip 1.1.1.1 dst-ip 3.3.3.3 service icmp type 4 code 3 status enable statistics enable

        result = dict()
        result['code'] = '200'
        result['msg'] = 'OK'
        result['data'] = None

        global conf_obj
        if conf_obj:
            s = conf_obj
        else:
            conf_obj = vfwcfg.loadf(src_file)
            s = conf_obj

        url = request.path.strip('/ ').rsplit('/', 1)
        if url[-1] == 'query':
            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
                #self.return_string = 'Not Found'
                #response = SecPolicyInCfgApi.make_response(self.return_string, 404)
                #return response
                result['code'] = '404'
                result['msg'] = 'Not Found'
                return jsonify(result)

            result['data'] = vfwcfg.sec_policy_in_rule_get(s, self.vrf, self.ip_proto, self.rule_id)
            return jsonify(result)

        if url[-1] == 'add':
            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
                #self.return_string = 'Bad Request'
                #response = SecPolicyInCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if self.ip_proto != 'v4' and self.ip_proto != 'v6':
                #self.return_string = 'Bad Request'
                #response = SecPolicyInCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if not self.rule_id:
                #self.return_string = 'Bad Request'
                #response = SecPolicyInCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if vfwcfg.sec_policy_in_rule_is_exist(s, self.vrf, self.ip_proto, self.rule_id):
                #self.return_string = 'Method Not Allowed'
                #response = SecPolicyInCfgApi.make_response(self.return_string, 405)
                #return response
                result['code'] = '405'
                result['msg'] = 'Already exist'
                return jsonify(result)

            vfwcfg.sec_policy_in_rule_add(s, self.vrf, self.ip_proto, self.rule_id,
                    status=self.status, action=self.action, service=self.service,
                    dst_port=self.dst_port, src_port=self.src_port,
                    dst_ip=self.dst_ip, src_ip=self.src_ip,
                    dst_ip6=self.dst_ip6, src_ip6=self.src_ip6,
                    description=self.desc)

            vfwcfg.dumpf(s, dst_file)
 
            msg = 'set secpolicy'

            if self.ip_proto == 'v4':
                msg += ' ip'
            if self.ip_proto == 'v6':
                msg += ' ipv6'

            if vfwcfg.get_fw_type():
                msg += ' tenant {} in2out-rule {}'.format(self.vrf, self.rule_id)
            else:
                msg += ' vrf {} in2out-rule {}'.format(self.vrf, self.rule_id)

            if self.action:
                msg += ' action {}'.format(self.action)

            if self.src_ip:
                msg += ' src-ip {}'.format(self.src_ip)

            if self.src_ip6:
                msg += ' src-ip6 {}'.format(self.src_ip6)

            if self.dst_ip:
                msg += ' dst-ip {}'.format(self.dst_ip)

            if self.dst_ip6:
                msg += ' dst-ip6 {}'.format(self.dst_ip6)

            if self.service:
                msg += ' service {}'.format(self.service)

            if self.icmp_type and self.service == 'icmp':
                msg += ' type {}'.format(self.icmp_type)

            if self.icmp_code and self.service == 'icmp':
                msg += ' code {}'.format(self.icmp_code)

            if self.src_port and self.service != 'icmp':
                ports = self.src_port.split('-')
                port_min = int(ports[0].strip())
                try:
                    port_max = int(ports[1].strip())
                except Exception:
                    port_max = port_min

                if port_max != port_min:
                    msg += ' src-port {} to {}'.format(port_min, port_max)
                    pass
                else:
                    msg += ' src-port {}'.format(port_min)

            if self.dst_port and self.service != 'icmp':
                ports = self.dst_port.split('-')
                port_min = int(ports[0].strip())
                try:
                    port_max = int(ports[1].strip())
                except Exception:
                    port_max = port_min

                if port_max != port_min:
                    msg += ' dst-port {} to {}'.format(port_min, port_max)
                    pass
                else:
                    msg += ' dst-port {}'.format(port_min)

            if self.app:
                msg += ' app {}'.format(self.app)

            if self.status:
                msg += ' status {}'.format(self.status)

            if self.statistics:
                msg += ' statistics {}'.format(self.statistics)

            # end
            self.msgs.append(msg)

            vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = SecPolicyInCfgApi.make_response(self.return_string, 200)
            #return jsonify(status = self.return_string)
            return jsonify(result)

        #def delete(self):
        if url[-1] == 'delele':
            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
                #self.return_string = 'OK'
                #response = SecPolicyInCfgApi.make_response(self.return_string, 200)
                #return response
                return jsonify(result)
            if self.ip_proto != 'v4' and self.ip_proto != 'v6':
                #self.return_string = 'Bad Request'
                #response = SecPolicyInCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)
            if not self.rule_id or not vfwcfg.sec_policy_in_rule_is_exist(s, self.vrf, self.ip_proto, self.rule_id):
                #self.return_string = 'OK'
                #response = SecPolicyInCfgApi.make_response(self.return_string, 200)
                #return jsonify(status = self.return_string)
                return jsonify(result)

            vfwcfg.sec_policy_in_rule_del(s, self.vrf, self.ip_proto, self.rule_id, action=self.action, src_ip=self.src_ip,
                    src_ip6=self.src_ip6, dst_ip=self.dst_ip, dst_ip6=self.dst_ip6, service=self.service, 
                    app=self.app, status=self.status, statistics=self.statistics)
            vfwcfg.dumpf(s, dst_file)

            # unset secpolicy ip vrf 1 in2out-rule 1 action src-ip dst-ip service app status statistics

            msg = 'unset secpolicy'

            if self.ip_proto == 'v4':
                msg += ' ip'

            if self.ip_proto == 'v6':
                msg += ' ipv6'

            if vfwcfg.get_fw_type():
                msg += ' tenant {} in2out-rule {}'.format(self.vrf, self.rule_id)
            else:
                msg += ' vrf {} in2out-rule {}'.format(self.vrf, self.rule_id)

            if self.action:
                msg += ' action'

            if self.src_ip:
                msg += ' src-ip'

            if self.src_ip6:
                msg += ' src-ip6'

            if self.dst_ip:
                msg += ' dst-ip'

            if self.dst_ip6:
                msg += ' dst-ip6'

            if self.service:
                msg += ' service'

            if self.app:
                msg += ' app'

            if self.status:
                msg += ' status'

            if self.statistics:
                msg += ' statistics'

            # end
            self.msgs.append(msg)

            vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = SecPolicyInCfgApi.make_response(self.return_string, 200)
            #return jsonify(status = self.return_string)
            return jsonify(result)

        # modify | merge
        #def put(self):
        if url[-1] == 'update':
            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
                #self.return_string = 'Bad Request'
                #response = SecPolicyInCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if self.ip_proto != 'v4' and self.ip_proto != 'v6':
                #self.return_string = 'Bad Request'
                #response = SecPolicyInCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if not self.rule_id or not vfwcfg.sec_policy_in_rule_is_exist(s, self.vrf, self.ip_proto, self.rule_id):
                #self.return_string = 'Bad Request'
                #response = SecPolicyInCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            vfwcfg.sec_policy_in_rule_modify(s, self.vrf, self.ip_proto, self.rule_id, action=self.action, src_ip=self.src_ip,
                    src_ip6=self.src_ip6, dst_ip=self.dst_ip, dst_ip6=self.dst_ip6, service=self.service, 
                    app=self.app, status=self.status, statistics=self.statistics)

            vfwcfg.dumpf(s, dst_file)

            msg = 'set secpolicy'

            if self.ip_proto == 'v4':
                msg += ' ip'
            if self.ip_proto == 'v6':
                msg += ' ipv6'

            if vfwcfg.get_fw_type():
                msg += ' tenant {} in2out-rule {}'.format(self.vrf, self.rule_id)
            else:
                msg += ' vrf {} in2out-rule {}'.format(self.vrf, self.rule_id)

            if self.action:
                msg += ' action {}'.format(self.action)

            if self.src_ip:
                msg += ' src-ip {}'.format(self.src_ip)

            if self.src_ip6:
                msg += ' src-ip6 {}'.format(self.src_ip6)

            if self.dst_ip:
                msg += ' dst-ip {}'.format(self.dst_ip)

            if self.dst_ip6:
                msg += ' dst-ip6 {}'.format(self.dst_ip6)

            if self.service:
                msg += ' service {}'.format(self.service)

            if self.icmp_type and self.service == 'icmp':
                msg += ' type {}'.format(self.icmp_type)

            if self.icmp_code and self.service == 'icmp':
                msg += ' code {}'.format(self.icmp_code)

            if self.src_port and self.service != 'icmp':
                ports = self.src_port.split('-')
                port_min = int(ports[0].strip())
                try:
                    port_max = int(ports[1].strip())
                except Exception:
                    port_max = port_min

                if port_max != port_min:
                    msg += ' src-port {} to {}'.format(port_min, port_max)
                    pass
                else:
                    msg += ' src-port {}'.format(port_min)

            if self.dst_port and self.service != 'icmp':
                ports = self.dst_port.split('-')
                port_min = int(ports[0].strip())
                try:
                    port_max = int(ports[1].strip())
                except Exception:
                    port_max = port_min

                if port_max != port_min:
                    msg += ' dst-port {} to {}'.format(port_min, port_max)
                    pass
                else:
                    msg += ' dst-port {}'.format(port_min)

            if self.app:
                msg += ' app {}'.format(self.app)

            if self.status:
                msg += ' status {}'.format(self.status)

            if self.statistics:
                msg += ' statistics {}'.format(self.statistics)

            # end
            vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = SecPolicyInCfgApi.make_response(self.return_string, 200)
            #return jsonify(status = self.return_string)
            return jsonify(result)

class SecPolicyOutCfg(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(trim = True, bundle_errors = True)
        self.reqparse.add_argument('uid',        type = str, default = '', location = 'json', required=True)
        self.reqparse.add_argument('ip_proto',   type = str, default = '', location = 'json')
        self.reqparse.add_argument('rule_id',    type = str, default = '', location = 'json')
        self.reqparse.add_argument('desc',       type = str, default = '', location = 'json')
        self.reqparse.add_argument('action',     type = str, default = '', location = 'json')
        self.reqparse.add_argument('dst_ip',     type = str, default = '', location = 'json')
        self.reqparse.add_argument('dst_ip6',    type = str, default = '', location = 'json')
        self.reqparse.add_argument('src_ip',     type = str, default = '', location = 'json')
        self.reqparse.add_argument('src_ip6',    type = str, default = '', location = 'json')
        self.reqparse.add_argument('service',    type = str, default = '', location = 'json')
        self.reqparse.add_argument('dst_port',   type = str, default = '', location = 'json')
        self.reqparse.add_argument('src_port',   type = str, default = '', location = 'json')
        self.reqparse.add_argument('icmp_type',  type = str, default = '', location = 'json')
        self.reqparse.add_argument('icmp_code',  type = str, default = '', location = 'json')
        self.reqparse.add_argument('app',        type = str, default = '', location = 'json')
        self.reqparse.add_argument('status',     type = str, default = '', location = 'json')
        self.reqparse.add_argument('statistics', type = str, default = '', location = 'json')

        self.args       = self.reqparse.parse_args(strict = True)
        self.vrf        = self.args['uid'].strip()
        self.ip_proto   = self.args['ip_proto'].strip()
        self.rule_id    = self.args['rule_id'].strip()
        self.desc       = self.args['desc']
        self.action     = self.args['action'].strip()
        self.dst_ip     = self.args['dst_ip'].strip()
        self.dst_ip6    = self.args['dst_ip6'].strip()  
        self.src_ip     = self.args['src_ip'].strip()
        self.src_ip6    = self.args['src_ip6'].strip()
        self.service    = self.args['service'].strip()
        self.dst_port   = self.args['dst_port'].strip()
        self.src_port   = self.args['src_port'].strip()
        self.icmp_type  = self.args['icmp_type'].strip()
        self.icmp_code  = self.args['icmp_code'].strip()
        self.app        = self.args['app'].strip()
        self.status     = self.args['status'].strip()
        self.statistics = self.args['statistics'].strip()
        self.msgs       = list()

    def post(self):
        result = dict()
        result['code'] = '200'
        result['msg'] = 'OK'
        result['data'] = None

        global conf_obj
        if conf_obj:
            s = conf_obj
        else:
            conf_obj = vfwcfg.loadf(src_file)
            s = conf_obj

        url = request.path.strip('/ ').rsplit('/', 1)
        if url[-1] == 'query':
            if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
                #self.return_string = 'Not Found'
                #response = SecPolicyOutCfgApi.make_response(self.return_string, 404)
                #return response
                result['code'] = '404'
                result['msg'] = 'Not Found'
                return jsonify(result)

            result['data'] = vfwcfg.sec_policy_out_rule_get(s, self.vrf, self.ip_proto, self.rule_id)
            return jsonify(result)

        if url[-1] == 'add':
            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
                #self.return_string = 'Bad Request'
                #response = SecPolicyOutCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if self.ip_proto != 'v4' and self.ip_proto != 'v6':
                #self.return_string = 'Bad Request'
                #response = SecPolicyOutCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if not self.rule_id:
                #self.return_string = 'Bad Request'
                #response = SecPolicyOutCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if vfwcfg.sec_policy_out_rule_is_exist(s, self.vrf, self.ip_proto, self.rule_id):
                #self.return_string = 'Method Not Allowed'
                #response = SecPolicyOutCfgApi.make_response(self.return_string, 405)
                #return response
                result['code'] = '405'
                result['msg'] = 'Already exist'
                return jsonify(result)

            vfwcfg.sec_policy_out_rule_add(s, self.vrf, self.ip_proto, self.rule_id,
                    status=self.status, action=self.action, service=self.service,
                    dst_port=self.dst_port, src_port=self.src_port,
                    dst_ip=self.dst_ip, src_ip=self.src_ip,
                    dst_ip6=self.dst_ip6, src_ip6=self.src_ip6,
                    description=self.desc)

            vfwcfg.dumpf(s, dst_file)

            msg = 'set secpolicy'

            if self.ip_proto == 'v4':
                msg += ' ip'
            if self.ip_proto == 'v6':
                msg += ' ipv6'

            if vfwcfg.get_fw_type():
                msg += ' tenant {} out2in-rule {}'.format(self.vrf, self.rule_id)
            else:
                msg += ' vrf {} out2in-rule {}'.format(self.vrf, self.rule_id)

            if self.action:
                msg += ' action {}'.format(self.action)

            if self.src_ip:
                msg += ' src-ip {}'.format(self.src_ip)

            if self.src_ip6:
                msg += ' src-ip6 {}'.format(self.src_ip6)

            if self.dst_ip:
                msg += ' dst-ip {}'.format(self.dst_ip)

            if self.dst_ip6:
                msg += ' dst-ip6 {}'.format(self.dst_ip6)

            if self.service:
                msg += ' service {}'.format(self.service)

            if self.icmp_type and self.service == 'icmp':
                msg += ' type {}'.format(self.icmp_type)

            if self.icmp_code and self.service == 'icmp':
                msg += ' code {}'.format(self.icmp_code)

            if self.src_port and self.service != 'icmp':
                ports = self.src_port.split('-')
                port_min = int(ports[0].strip())
                try:
                    port_max = int(ports[1].strip())
                except Exception:
                    port_max = port_min

                if port_max != port_min:
                    msg += ' src-port {} to {}'.format(port_min, port_max)
                    pass
                else:
                    msg += ' src-port {}'.format(port_min)

            if self.dst_port and self.service != 'icmp':
                ports = self.dst_port.split('-')
                port_min = int(ports[0].strip())
                try:
                    port_max = int(ports[1].strip())
                except Exception:
                    port_max = port_min

                if port_max != port_min:
                    msg += ' dst-port {} to {}'.format(port_min, port_max)
                    pass
                else:
                    msg += ' dst-port {}'.format(port_min)

            if self.app:
                msg += ' app {}'.format(self.app)

            if self.status:
                msg += ' status {}'.format(self.status)

            if self.statistics:
                msg += ' statistics {}'.format(self.statistics)

            # end
            self.msgs.append(msg)

            vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = SecPolicyOutCfgApi.make_response(self.return_string, 200)
            #return jsonify(status = self.return_string)
            return jsonify(result)

        #def delete(self):
        if url[-1] == 'delete':
            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
                #self.return_string = 'OK'
                #response = SecPolicyOutCfgApi.make_response(self.return_string, 200)
                #return response
                return jsonify(result)

            if self.ip_proto != 'v4' and self.ip_proto != 'v6':
                #self.return_string = 'Bad Request'
                #response = SecPolicyOutCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if not self.rule_id or not vfwcfg.sec_policy_out_rule_is_exist(s, self.vrf, self.ip_proto, self.rule_id):
                #self.return_string = 'OK'
                #response = SecPolicyOutCfgApi.make_response(self.return_string, 200)
                #return jsonify(status = self.return_string)
                return jsonify(result)

            vfwcfg.sec_policy_out_rule_del(s, self.vrf, self.ip_proto, self.rule_id, action=self.action, src_ip=self.src_ip,
                    src_ip6=self.src_ip6, dst_ip=self.dst_ip, dst_ip6=self.dst_ip6, service=self.service, 
                    app=self.app, status=self.status, statistics=self.statistics)

            vfwcfg.dumpf(s, dst_file)

            # unset secpolicy ip vrf 1 out2in-rule 1 action src-ip dst-ip service app status statistics
            msg = 'unset secpolicy'

            if self.ip_proto == 'v4':
                msg += ' ip'

            if self.ip_proto == 'v6':
                msg += ' ipv6'

            if vfwcfg.get_fw_type():
                msg += ' tenant {} out2in-rule {}'.format(self.vrf, self.rule_id)
            else:
                msg += ' vrf {} out2in-rule {}'.format(self.vrf, self.rule_id)

            if self.action:
                msg += ' action'

            if self.src_ip:
                msg += ' src-ip'

            if self.src_ip6:
                msg += ' src-ip6'

            if self.dst_ip:
                msg += ' dst-ip'

            if self.dst_ip6:
                msg += ' dst-ip6'

            if self.service:
                msg += ' service'

            if self.app:
                msg += ' app'

            if self.status:
                msg += ' status'

            if self.statistics:
                msg += ' statistics'

            # end
            self.msgs.append(msg)

            vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = SecPolicyOutCfgApi.make_response(self.return_string, 200)
            #return jsonify(status = self.return_string)
            return jsonify(result)

        # modify | merge
        # def patch(self):
        if url[-1] == 'update':
            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
                #self.return_string = 'Bad Request'
                #response = SecPolicyOutCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if self.ip_proto != 'v4' and self.ip_proto != 'v6':
                #self.return_string = 'Bad Request'
                #response = SecPolicyOutCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if not self.rule_id or not vfwcfg.sec_policy_out_rule_is_exist(s, self.vrf, self.ip_proto, self.rule_id):
                #self.return_string = 'Bad Request'
                #response = SecPolicyOutCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            vfwcfg.sec_policy_out_rule_modify(s, self.vrf, self.ip_proto, self.rule_id, action=self.action, src_ip=self.src_ip,
                    src_ip6=self.src_ip6, dst_ip=self.dst_ip, dst_ip6=self.dst_ip6, service=self.service, 
                    app=self.app, status=self.status, statistics=self.statistics)
            vfwcfg.dumpf(s, dst_file)

            msg = 'set secpolicy'

            if self.ip_proto == 'v4':
                msg += ' ip'
            if self.ip_proto == 'v6':
                msg += ' ipv6'

            if vfwcfg.get_fw_type():
                msg += ' tenant {} out2in-rule {}'.format(self.vrf, self.rule_id)
            else:
                msg += ' vrf {} out2in-rule {}'.format(self.vrf, self.rule_id)

            if self.action:
                msg += ' action {}'.format(self.action)

            if self.src_ip:
                msg += ' src-ip {}'.format(self.src_ip)

            if self.src_ip6:
                msg += ' src-ip6 {}'.format(self.src_ip6)

            if self.dst_ip:
                msg += ' dst-ip {}'.format(self.dst_ip)

            if self.dst_ip6:
                msg += ' dst-ip6 {}'.format(self.dst_ip6)

            if self.service:
                msg += ' service {}'.format(self.service)

            if self.icmp_type and self.service == 'icmp':
                msg += ' type {}'.format(self.icmp_type)

            if self.icmp_code and self.service == 'icmp':
                msg += ' code {}'.format(self.icmp_code)

            if self.src_port and self.service != 'icmp':
                ports = self.src_port.split('-')
                port_min = int(ports[0].strip())
                try:
                    port_max = int(ports[1].strip())
                except Exception:
                    port_max = port_min

                if port_max != port_min:
                    msg += ' src-port {} to {}'.format(port_min, port_max)
                    pass
                else:
                    msg += ' src-port {}'.format(port_min)

            if self.dst_port and self.service != 'icmp':
                ports = self.dst_port.split('-')
                port_min = int(ports[0].strip())
                try:
                    port_max = int(ports[1].strip())
                except Exception:
                    port_max = port_min

                if port_max != port_min:
                    msg += ' dst-port {} to {}'.format(port_min, port_max)
                    pass
                else:
                    msg += ' dst-port {}'.format(port_min)

            if self.app:
                msg += ' app {}'.format(self.app)

            if self.status:
                msg += ' status {}'.format(self.status)

            if self.statistics:
                msg += ' statistics {}'.format(self.statistics)

            # end
            self.msgs.append(msg)
            vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = SecPolicyOutCfgApi.make_response(self.return_string, 200)
            #return jsonify(status = self.return_string)
            return jsonify(result)

class SecPolicyInOrderCfg(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(trim = True, bundle_errors = True)
        self.reqparse.add_argument('uid',      type = str, default = '', location = 'json', required=True)
        self.reqparse.add_argument('ip_proto', type = str, default = '', location = 'json')
        self.reqparse.add_argument('rule_id',  type = str, default = '', location = 'json')
        self.reqparse.add_argument('base',     type = str, default = '', location = 'json')
        self.reqparse.add_argument('action',   type = str, default = '', location = 'json')
        self.reqparse.add_argument('pos',      type = str, default = '', location = 'json')

        self.args      = self.reqparse.parse_args(strict = True)
        self.vrf       = self.args['uid'].strip()
        self.ip_proto  = self.args['ip_proto'].strip()
        self.rule_id   = self.args['rule_id'].strip()
        self.base      = self.args['base'].strip()
        self.action    = self.args['action'].strip()
        self.pos       = self.args['pos'].strip()
        self.msgs      = list()

    def post(self):
        result = dict()
        result['code'] = '200'
        result['msg'] = 'OK'
        result['data'] = None

        global conf_obj
        if conf_obj:
            s = conf_obj
        else:
            conf_obj = vfwcfg.loadf(src_file)
            s = conf_obj

        url = request.path.strip('/ ').rsplit('/', 1)
        if url[-1] == 'update':
            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
                #self.return_string = 'Bad Request'
                #response = SecPolicyInOrderApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if self.ip_proto != 'v4' and self.ip_proto != 'v6':
                #self.return_string = 'Bad Request'
                #response = SecPolicyInOrderApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if not self.rule_id or not vfwcfg.sec_policy_in_rule_is_exist(s, self.vrf, self.ip_proto, self.rule_id):
                #self.return_string = 'Bad Request'
                #response = SecPolicyInOrderApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if self.pos and self.action:
                #self.return_string = 'Bad Request'
                #response = SecPolicyInOrderApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if not self.pos and not self.action:
                #self.return_string = 'Bad Request'
                #response = SecPolicyInOrderApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if self.action:
                if self.action != 'after' and self.action != 'before':
                    #self.return_string = 'Bad Request'
                    #response = SecPolicyInOrderApi.make_response(self.return_string, 400)
                    #return response
                    result['code'] = '400'
                    result['msg'] = 'Invalid parameter'
                    return jsonify(result)

                if not self.base or not vfwcfg.sec_policy_in_rule_is_exist(s, self.vrf, self.ip_proto, self.base):
                    #self.return_string = 'Bad Request'
                    #response = SecPolicyInOrderApi.make_response(self.return_string, 400)
                    #return response
                    result['code'] = '400'
                    result['msg'] = 'Invalid parameter'
                    return jsonify(result)

                if self.base != self.rule_id:
                    vfwcfg.sec_policy_in_rule_order(s, self.vrf, self.ip_proto, self.rule_id, base=self.base, action=self.action)
                    vfwcfg.dumpf(s, dst_file)

                    # after | before
                    if self.ip_proto == 'v4':
                        if vfwcfg.get_fw_type():
                            self.msgs.append('move secpolicy ip tenant {} in2out-rule {} {} {}'.format(self.vrf, self.rule_id, self.action, self.base))
                        else:
                            self.msgs.append('move secpolicy ip vrf {} in2out-rule {} {} {}'.format(self.vrf, self.rule_id, self.action, self.base))

                    if self.ip_proto == 'v6':
                        if vfwcfg.get_fw_type():
                            self.msgs.append('move secpolicy ipv6 tenant {} in2out-rule {} {} {}'.format(self.vrf, self.rule_id, self.action, self.base))
                        else:
                            self.msgs.append('move secpolicy ipv6 vrf {} in2out-rule {} {} {}'.format(self.vrf, self.rule_id, self.action, self.base))

                    vfw_send(self.msgs)

            if self.pos:
                if self.pos != 'head' and self.pos!= 'tail':
                    #self.return_string = 'Bad Request'
                    #response = SecPolicyInOrderApi.make_response(self.return_string, 400)
                    #return response
                    result['code'] = '400'
                    result['msg'] = 'Invalid parameter'
                    return jsonify(result)

                vfwcfg.sec_policy_in_rule_order(s, self.vrf, self.ip_proto, self.rule_id, pos=self.pos)
                vfwcfg.dumpf(s, dst_file)

                # head | tail
                if self.ip_proto == 'v4':
                    if vfwcfg.get_fw_type():
                        self.msgs.append('move secpolicy ip tenant {} in2out-rule {} {}'.format(self.vrf, self.rule_id, self.pos))
                    else:
                        self.msgs.append('move secpolicy ip vrf {} in2out-rule {} {}'.format(self.vrf, self.rule_id, self.pos))

                if self.ip_proto == 'v6':
                    if vfwcfg.get_fw_type():
                        self.msgs.append('move secpolicy ipv6 tenant {} in2out-rule {} {}'.format(self.vrf, self.rule_id, self.pos))
                    else:
                        self.msgs.append('move secpolicy ipv6 vrf {} in2out-rule {} {}'.format(self.vrf, self.rule_id, self.pos))

                vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = SecPolicyInOrderApi.make_response(self.return_string, 200)
            #return jsonify(ret = self.return_string)
            return jsonify(result)

class SecPolicyOutOrderCfg(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(trim = True, bundle_errors = True)
        self.reqparse.add_argument('uid',      type = str, default = '', location = 'json', required=True)
        self.reqparse.add_argument('ip_proto', type = str, default = '', location = 'json')
        self.reqparse.add_argument('rule_id',  type = str, default = '', location = 'json')
        self.reqparse.add_argument('base',     type = str, default = '', location = 'json')
        self.reqparse.add_argument('action',   type = str, default = '', location = 'json')
        self.reqparse.add_argument('pos',      type = str, default = '', location = 'json')

        self.args     = self.reqparse.parse_args(strict = True)
        self.vrf      = self.args['uid'].strip()
        self.ip_proto = self.args['ip_proto'].strip()
        self.rule_id  = self.args['rule_id'].strip()
        self.base     = self.args['base'].strip()
        self.action   = self.args['action'].strip()
        self.pos      = self.args['pos'].strip()
        self.msgs     = list()

    def post(self):
        result = dict()
        result['code'] = '200'
        result['msg'] = 'OK'
        result['data'] = None

        global conf_obj
        if conf_obj:
            s = conf_obj
        else:
            conf_obj = vfwcfg.loadf(src_file)
            s = conf_obj

        url = request.path.strip('/ ').rsplit('/', 1)
        if url[-1] == 'update':
            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
                #self.return_string = 'Bad Request'
                #response = SecPolicyOutOrderApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if self.ip_proto != 'v4' and self.ip_proto != 'v6':
                #self.return_string = 'Bad Request'
                #response = SecPolicyOutOrderApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if not self.rule_id or not vfwcfg.sec_policy_out_rule_is_exist(s, self.vrf, self.ip_proto, self.rule_id):
                #self.return_string = 'Bad Request'
                #response = SecPolicyOutOrderApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if self.pos and self.action:
                #self.return_string = 'Bad Request'
                #response = SecPolicyOutOrderApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if not self.pos and not self.action:
                #self.return_string = 'Bad Request'
                #response = SecPolicyOutOrderApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)


            if self.action:
                if self.action != 'after' and self.action != 'before':
                    #self.return_string = 'Bad Request'
                    #response = SecPolicyOutOrderApi.make_response(self.return_string, 400)
                    #return response
                    result['code'] = '400'
                    result['msg'] = 'Invalid parameter'
                    return jsonify(result)

                if not self.base or not vfwcfg.sec_policy_in_rule_is_exist(s, self.vrf, self.ip_proto, self.base):
                    #self.return_string = 'Bad Request'
                    #response = SecPolicyOutOrderApi.make_response(self.return_string, 400)
                    #return response
                    result['code'] = '400'
                    result['msg'] = 'Invalid parameter'
                    return jsonify(result)

                if self.base != self.rule_id:
                    vfwcfg.sec_policy_out_rule_order(s, self.vrf, self.ip_proto, self.rule_id, base=self.base, action=self.action)
                    vfwcfg.dumpf(s, dst_file)

                    # after | before
                    if self.ip_proto == 'v4':
                        if vfwcfg.get_fw_type():
                            self.msgs.append('move secpolicy ip tenant {} out2in-rule {} {} {}'.format(self.vrf, self.rule_id, self.action, self.base))
                        else:
                            self.msgs.append('move secpolicy ip vrf {} out2in-rule {} {} {}'.format(self.vrf, self.rule_id, self.action, self.base))

                    if self.ip_proto == 'v6':
                        if vfwcfg.get_fw_type():
                            self.msgs.append('move secpolicy ipv6 tenant {} out2in-rule {} {} {}'.format(self.vrf, self.rule_id, self.action, self.base))
                        else:
                            self.msgs.append('move secpolicy ipv6 vrf {} out2in-rule {} {} {}'.format(self.vrf, self.rule_id, self.action, self.base))

                    vfw_send(self.msgs)

            if self.pos:
                if self.pos != 'head' and self.pos != 'tail':
                    #self.return_string = 'Bad Request'
                    #response = SecPolicyOutOrderApi.make_response(self.return_string, 400)
                    #return response
                    result['code'] = '400'
                    result['msg'] = 'Invalid parameter'
                    return jsonify(result)

                vfwcfg.sec_policy_out_rule_order(s, self.vrf, self.ip_proto, self.rule_id, self.base, self.action)
                vfwcfg.dumpf(s, dst_file)

                # head | tail
                if self.ip_proto == 'v4':
                    if vfwcfg.get_fw_type():
                        self.msgs.append('move secpolicy ip tenant {} out2in-rule {} {}'.format(self.vrf, self.rule_id, self.pos))  
                    else:
                        self.msgs.append('move secpolicy ip vrf {} out2in-rule {} {}'.format(self.vrf, self.rule_id, self.pos))  

                if self.ip_proto == 'v6':
                    if vfwcfg.get_fw_type():
                        self.msgs.append('move secpolicy ipv6 tenant {} out2in-rule {} {}'.format(self.vrf, self.rule_id, self.pos))
                    else:
                        self.msgs.append('move secpolicy ipv6 vrf {} out2in-rule {} {}'.format(self.vrf, self.rule_id, self.pos))

                vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = SecPolicyOutOrderApi.make_response(self.return_string, 200)
            #return jsonify(ret = self.return_string)
            return jsonify(result)

class VrfCfg(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(trim = True, bundle_errors = True)
        self.reqparse.add_argument('uid', type = str, location = 'json', required=True)

        self.args  = self.reqparse.parse_args(strict = True)
        self.vrf   = self.args['uid'].strip()
        self.msgs  = list()

    def post(self):
        result = dict()
        result['code'] = '200'
        result['msg'] = 'OK'
        result['data'] = None

        global conf_obj
        if conf_obj:
            s = conf_obj
        else:
            conf_obj = vfwcfg.loadf(src_file)
            s = conf_obj

        url = request.path.strip('/ ').rsplit('/', 1)
        if url[-1] == 'query':
            return jsonify(result)

        if url[-1] == 'add':
            # convert uuid to id
            uid = self.vrf
            self.vrf = vfwcfg.uid_get(s, self.vrf, 'add')

            if not self.vrf or vfwcfg.vrf_is_exist(s, self.vrf):
                #self.return_string = 'Bad Request'
                #response = VrfCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            vfwcfg.vrf_add(s, self.vrf)
            vfwcfg.dumpf(s, dst_file)

            self.msgs.append('create vrf {} user-id {}'.format(self.vrf, uid))
            vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = VrfCfgApi.make_response(self.return_string, 200)
            #return jsonify(ret = self.return_string)
            return jsonify(result)

        # def delete(self):
        if url[-1] == 'delete':
            # convert uuid to id
            uid = self.vrf
            self.vrf = vfwcfg.uid_get(s, self.vrf)

            if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
                #self.return_string = 'OK'
                #response = VrfCfgApi.make_response(self.return_string, 200)
                #return jsonify(status = self.return_string)
                return jsonify(result)

            vfwcfg.vrf_del(s, self.vrf)
            vfwcfg.dumpf(s, dst_file)

            self.msgs.append('delete vrf {} user-id {}'.format(self.vrf, uid))
            vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = VrfCfgApi.make_response(self.return_string, 200)
            #return jsonify(ret = self.return_string)
            return jsonify(result)

class IpsCfg(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(trim = True, bundle_errors = True)
        self.reqparse.add_argument('uid',     type = str, location = 'json', required=True)
        self.reqparse.add_argument('vpatch',  type = str, default = '', location = 'json')
        self.reqparse.add_argument('runmode', type = str, default = '', location = 'json')

        self.args = self.reqparse.parse_args(strict = True)
        self.vrf     = self.args['uid'].strip()
        self.vpatch  = self.args['vpatch'].strip()
        self.runmode = self.args['runmode'].strip()
        self.msgs    = list()

    def post(self):
        result = dict()
        result['code'] = '200'
        result['msg'] = 'OK'
        result['data'] = None

        global conf_obj
        if conf_obj:
            s = conf_obj
        else:
            conf_obj = vfwcfg.loadf(src_file)
            s = conf_obj

        url = request.path.strip('/ ').rsplit('/', 1)
        if url[-1] == 'query':
            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            result['data'] = vfwcfg.ips_cfg_get(s, self.vrf)
            return jsonify(result)

        if url[-1] == 'update':
            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            switch_list = ['on', 'off']
            if not self.vpatch in switch_list:
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            mode_list = ['block', 'monitor']
            if not self.runmode in mode_list:
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            vfwcfg.ips_cfg_set(s, self.vrf, vpatch=self.vpatch, runmode=self.runmode)
            vfwcfg.dumpf(s, dst_file)

            self.msgs.append('set vrf {} vpatch {}'.format(self.vrf, self.vpatch))
            self.msgs.append('set vrf {} dpi-mode {}'.format(self.vrf, self.runmode))
            vfw_send(self.msgs)

            return jsonify(result)

class IpsRuleCfg(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(trim = True, bundle_errors = True)
        self.reqparse.add_argument('uid',     type = str, location = 'json', required=True)
        self.reqparse.add_argument('rule_id', type = str, location = 'json', default = '')
        self.reqparse.add_argument('action',  type = str, location = 'json', default = '', choices = ('pass', 'drop', 'alert'))
        self.reqparse.add_argument('method',  type = str, location = 'json', default = '')
        self.reqparse.add_argument('target',  type = str, location = 'json', default = '')
        self.reqparse.add_argument('type',    type = str, location = 'json', default = '')
        self.reqparse.add_argument('offset',  type = int, location = 'json', default = 0,)
        self.reqparse.add_argument('count',   type = int, location = 'json', default = 50)

        self.args = self.reqparse.parse_args(strict = True)
        self.vrf     = self.args['uid'].strip()
        self.rule_id = self.args['rule_id'].strip()
        self.action  = self.args['action'].strip()
        self.method  = self.args['method'].strip()
        self.target  = self.args['target'].strip()
        self.type    = self.args['type'].strip()
        self.offset  = self.args['offset']
        self.count   = self.args['count']
        self.msgs    = list()

    # modify | merge
    def post(self):
        result = dict()
        result['code'] = '200'
        result['msg'] = 'OK'
        result['data'] = None

        global conf_obj
        if conf_obj:
            s = conf_obj
        else:
            conf_obj = vfwcfg.loadf(src_file)
            s = conf_obj

        url = request.path.strip('/ ').rsplit('/', 1)
        if url[-1] == 'update':
            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
                #self.return_string = 'Bad Request'
                #response = IpsRuleCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if not self.rule_id or int(self.rule_id) not in dict_ips_rules.keys():
                #self.return_string = 'Bad Request'
                #response = IpsRuleCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            info = dict_ips_rules.get(int(self.rule_id))
            if info['act'] == self.action:
                # restore defaults
                vfwcfg.ips_policy_delete(s, self.vrf, self.rule_id)
            else:
                # modify action
                vfwcfg.ips_policy_modify(s, self.vrf, self.rule_id, self.action)

            vfwcfg.dumpf(s, dst_file)

            self.msgs.append('set vrf {} ips-policy rule {} action {}'.format(self.vrf, self.rule_id, self.action))
            vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = IpsRuleCfgApi.make_response(self.return_string, 200)
            #return jsonify(status = self.return_string)
            return jsonify(result)

        if url[-1] == 'query':
            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
                #self.return_string = 'Bad Request'
                #response = IpsRuleCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if self.rule_id:
                info = dict_ips_rules.get(int(self.rule_id))
                if not info:
                    #self.return_string = 'Not Found'
                    #response = IpsRuleCfgApi.make_response(self.return_string, 404)
                    #return response
                    result['code'] = '404'
                    result['msg'] = 'Not Found'
                    return jsonify(result)

                rule_info = copy.deepcopy(info)
                action = vfwcfg.ips_policy_get(s, self.vrf, self.rule_id)
                if action:
                    rule_info['user_act'] = action
                else:
                    rule_info['user_act'] = rule_info['act']

                rule_info.pop('gid', None)
                rule_info.pop('act', None)
                data = dict()
                data[self.rule_id] = rule_info
                result['data'] = data 
                return jsonify(result)

            if self.type != 'vpatch' and self.type != 'base':
                #self.return_string = 'Bad Request'
                #response = IpsRuleCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            id_list = list()
            if self.method or self.target:
                method_list = list()
                target_list = list()

                if self.method:
                    if self.type == 'vpatch':
                        method_list = dict_ips_vpatch_method[self.method]
                    else:
                        method_list = dict_ips_base_method[self.method]

                if self.target:
                    if self.type == 'vpatch':
                        target_list = dict_ips_vpatch_target[self.target]
                    else:
                        target_list = dict_ips_base_target[self.target]

                if method_list and target_list:
                    id_list = [i for i in method_list if i in target_list]
                elif method_list:
                    id_list = method_list
                else:
                    id_list = target_list
            else:
                if self.type == 'vpatch':
                    id_list = list_ips_vpatch_rules
                else:
                    id_list = list_ips_base_rules

            data = dict()
            rule_ids = id_list[self.offset:self.offset+self.count]

            for rule_id in rule_ids:
                info = dict_ips_rules.get(rule_id)
                if not info:
                    continue

                rule_info = copy.deepcopy(info)

                action = vfwcfg.ips_policy_get(s, self.vrf, rule_id)
                if action:
                    rule_info['user_act'] = action
                else:
                    rule_info['user_act'] = rule_info['act']

                rule_info.pop('gid', None)
                rule_info.pop('act', None)
                data[rule_id] = rule_info

            #return result
            result['data'] = data
            return jsonify(result)

class VlanPortCfg(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(trim = True, bundle_errors = True)
        self.reqparse.add_argument('portname', type = str, default = '', location = 'json')
        self.reqparse.add_argument('link',     type = str, default = '', location = 'json')
        self.reqparse.add_argument('id',       type = str, default = '', location = 'json')

        self.args = self.reqparse.parse_args(strict = True)
        self.portname  = self.args['portname'].strip()
        self.link      = self.args['link'].strip()
        self.id        = self.args['id'].strip()
        self.msgs      = list()

    # create
    def post(self):
        result = dict()
        result['code'] = '200'
        result['msg'] = 'OK'
        result['data'] = None

        global conf_obj
        if conf_obj:
            s = conf_obj
        else:
            conf_obj = vfwcfg.loadf(src_file)
            s = conf_obj

        url = request.path.strip('/ ').rsplit('/', 1)
        if url[-1] == 'query':
            result['data'] = vfwcfg.get_vlan_port_cfg(s, self.portname)
            return jsonify(result)

        if url[-1] == 'add':
            if not self.portname or self.portname in vfwcfg.get_vlanportlist(s):
                #self.return_string = 'Bad Request'
                #response = VlanPortCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if not self.link or self.link not in vfwcfg.get_portlist(s):
                #self.return_string = 'Bad Request'
                #response = VlanPortCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            vfwcfg.create_vlan_port(s, 'add', self.portname, self.link, self.id)
            vfwcfg.dumpf(s, dst_file)

            self.msgs.append('set vlan {} link {} id {}'.format(self.portname, self.link, self.id))
            vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = VlanPortCfgApi.make_response(self.return_string, 200)
            #return jsonify(status = self.return_string)
            return jsonify(result)

        # delete
        # def delete(self):
        if url[-1] == 'delete':
            if not self.portname:
                #self.return_string = 'Bad Request'
                #response = VlanPortCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            vfwcfg.create_vlan_port(s, 'del', self.portname)
            vfwcfg.dumpf(s, dst_file)

            self.msgs.append('unset vlan {}'.format(self.portname))
            vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = VlanPortCfgApi.make_response(self.return_string, 200)
            #return jsonify(status = self.return_string)
            return jsonify(result)

class PortIPCfg(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(trim = True, bundle_errors = True)
        self.reqparse.add_argument('portname', type = str, default = '', location = 'json')
        self.reqparse.add_argument('ip',       type = str, default = '', location = 'json')
        self.reqparse.add_argument('ip6',      type = str, default = '', location = 'json')

        self.args = self.reqparse.parse_args(strict = True)
        self.portname = self.args['portname'].strip()
        self.ip       = self.args['ip'].strip()
        self.ip6      = self.args['ip6'].strip()
        self.msgs     = list()

    # set interface ip
    def post(self):
        result = dict()
        result['code'] = '200'
        result['msg'] = 'OK'
        result['data'] = None

        global conf_obj
        if conf_obj:
            s = conf_obj
        else:
            conf_obj = vfwcfg.loadf(src_file)
            s = conf_obj

        url = request.path.strip('/ ').rsplit('/', 1)
        if url[-1] == 'update':
            #if not self.portname or self.portname not in vfwcfg.get_portlist(s):
            if not self.portname:
                #self.return_string = 'Bad Request'
                #response = PortIPCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if self.ip:
                ip_list = self.ip.split(',')
                for i in ip_list:
                    vfwcfg.set_port_ip_list(s, self.portname, 'add', ip=i.strip())
                    self.msgs.append('set address add {} interface {}'.format(i.strip(), self.portname))

            if self.ip6:
                ip_list = self.ip6.split(',')
                for i in ip_list:
                    vfwcfg.set_port_ip_list(s, self.portname, 'add', ip6=i.strip())
                    self.msgs.append('set address v6 add {} interface {}'.format(i.strip(), self.portname))

            vfwcfg.dumpf(s, dst_file)

            vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = PortIPCfgApi.make_response(self.return_string, 200)
            #return jsonify(status = self.return_string)
            return jsonify(result)

        # delete interface ip
        # def delete(self):
        if url[-1] == 'delete':
            #if not self.portname or self.portname not in vfwcfg.get_portlist(s):
            if not self.portname:
                #self.return_string = 'Bad Request'
                #response = PortIPCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if self.ip:
                ip_list = self.ip.split(',')
                for i in ip_list:
                    vfwcfg.set_port_ip_list(s, self.portname, 'del', ip=i.strip())
                    self.msgs.append('unset address add {} interface {}'.format(i.strip(), self.portname))

            if self.ip6:
                ip_list = self.ip6.split(',')
                for i in ip_list:
                    vfwcfg.set_port_ip_list(s, self.portname, 'del', ip6=i.strip())
                    self.msgs.append('unset address v6 add {} interface {}'.format(i.strip(), self.portname))

            vfwcfg.dumpf(s, dst_file)

            vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = PortIPCfgApi.make_response(self.return_string, 200)
            #return jsonify(status = self.return_string)
            return jsonify(result)

        if url[-1] == 'query':
            result['data'] = vfwcfg.get_port_ip_list(s, self.portname)
            return jsonify(result)

class RouteCfg(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(trim = True, bundle_errors = True)
        self.reqparse.add_argument('uid',         type = str, default = '', location = 'json', required=True)
        self.reqparse.add_argument('proto',       type = str, default = '', location = 'json')
        self.reqparse.add_argument('dip',         type = str, default = '', location = 'json')
        self.reqparse.add_argument('netmask',     type = str, default = '', location = 'json')
        self.reqparse.add_argument('prefix_len',  type = str, default = '', location = 'json')
        self.reqparse.add_argument('gw',          type = str, default = '', location = 'json')
        self.reqparse.add_argument('port',        type = str, default = '', location = 'json')
        self.reqparse.add_argument('type',        type = str, default = '', location = 'json')

        self.args = self.reqparse.parse_args(strict = True)
        self.vrf            = self.args['uid'].strip()
        self.proto          = self.args['proto'].strip()
        self.dip            = self.args['dip'].strip()
        self.netmask        = self.args['netmask'].strip()
        self.prefix_len     = self.args['prefix_len'].strip()
        self.gw             = self.args['gw'].strip()
        self.port           = self.args['port'].strip()
        self.type           = self.args['type'].strip()
        self.msgs      = list()

    # create
    def post(self):
        result = dict()
        result['code'] = '200'
        result['msg'] = 'OK'
        result['data'] = None

        global conf_obj
        if conf_obj:
            s = conf_obj
        else:
            conf_obj = vfwcfg.loadf(src_file)
            s = conf_obj

        url = request.path.strip('/ ').rsplit('/', 1)
        if url[-1] == 'add':
            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
                #self.return_string = 'Bad Request'
                #response = RouteCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            #if not self.port or self.port not in vfwcfg.get_portlist(s):
            if not self.port:
                #self.return_string = 'Bad Request'
                #response = RouteCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if not self.proto or not self.dip or not self.gw or not self.type:
                #self.return_string = 'Bad Request'
                #response = RouteCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if self.proto != 'v4' and self.proto != 'v6':
                #self.return_string = 'Bad Request'
                #response = RouteCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if self.proto == 'v4' and not self.netmask:
                #self.return_string = 'Bad Request'
                #response = RouteCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if self.proto == 'v6' and not self.prefix_len:
                #self.return_string = 'Bad Request'
                #response = RouteCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if self.proto == 'v4':
                if vfwcfg.route_is_exist(s, self.vrf, self.proto, dip = self.dip, netmask = self.netmask, gw = self.gw, port = self.port, type = self.type):
                    #self.return_string = 'Bad Request'
                    #response = RouteCfgApi.make_response(self.return_string, 400)
                    #return response
                    result['code'] = '400'
                    result['msg'] = 'Invalid parameter'
                    return jsonify(result)

                vfwcfg.route_add(s, self.vrf, self.proto, dip = self.dip, netmask = self.netmask, gw = self.gw, port = self.port, type = self.type)
                vfwcfg.dumpf(s, dst_file)

                # set route tid 1 dip 1.1.1.1 gw 1.1.1.1 netmask 24 port dpdk0 net|local
                self.msgs.append('set route tid {} dip {} gw {} netmask {} port {} {}'.format(self.vrf, self.dip, self.gw, self.netmask, self.port, self.type))
                vfw_send(self.msgs)

            if self.proto == 'v6':
                if vfwcfg.route_is_exist(s, self.vrf, self.proto, dip = self.dip, prefix_len = self.prefix_len, gw = self.gw, port = self.port, type = self.type):
                    #self.return_string = 'Bad Request'
                    #response = RouteCfgApi.make_response(self.return_string, 400)
                    #return response
                    result['code'] = '400'
                    result['msg'] = 'Invalid parameter'
                    return jsonify(result)

                vfwcfg.route_add(s, self.vrf, self.proto, dip = self.dip, prefix_len = self.prefix_len, gw = self.gw, port = self.port, type = self.type)
                vfwcfg.dumpf(s, dst_file)

                # set route6 tid 2 dip 1::1 prefix-len 96 gw 1::1 port dpdk0 net|local
                self.msgs.append('set route6 tid {} dip {} prefix-len {} gw {} port {} {}'.format(self.vrf, self.dip, self.prefix_len, self.gw, self.port, self.type))
                vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = RouteCfgApi.make_response(self.return_string, 200)
            #return jsonify(status = self.return_string)
            return jsonify(result)

        # delete route
        # def delete(self):
        if url[-1] == 'delete':
            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
                #self.return_string = 'Bad Request'
                #response = RouteCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if not self.dip:
                if self.proto != 'v4' and self.proto != 'v6':
                    #self.return_string = 'Bad Request'
                    #response = RouteCfgApi.make_response(self.return_string, 400)
                    #return response
                    result['code'] = '400'
                    result['msg'] = 'Invalid parameter'
                    return jsonify(result)

                # delete all route in vrf
                vfwcfg.route_del_all(s, self.vrf, self.proto)
                vfwcfg.dumpf(s, dst_file)

                if self.proto == 'v4':
                    # unset route tid 2
                    self.msgs.append('unset route tid {}'.format(self.vrf))

                if self.proto == 'v6':
                    # unset route6 tid 2
                    self.msgs.append('unset route6 tid {}'.format(self.vrf))

                vfw_send(self.msgs)

                #self.return_string = 'OK'
                #response = RouteCfgApi.make_response(self.return_string, 200)
                #return jsonify(status = self.return_string)
                return jsonify(result)

            #if not self.port or self.port not in vfwcfg.get_portlist(s):
            if not self.port:
                #self.return_string = 'Bad Request'
                #response = RouteCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if not self.proto or not self.type:
                #self.return_string = 'Bad Request'
                #response = RouteCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if self.proto != 'v4' and self.proto != 'v6':
                #self.return_string = 'Bad Request'
                #response = RouteCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if self.proto == 'v4' and not self.netmask:
                #self.return_string = 'Bad Request'
                #response = RouteCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if self.proto == 'v6' and not self.prefix_len:
                #self.return_string = 'Bad Request'
                #response = RouteCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            ret = False
            if self.proto == 'v4':
                ret = vfwcfg.route_del(s, self.vrf, self.proto, dip = self.dip, netmask = self.netmask, port = self.port, type = self.type)
                if ret:
                    vfwcfg.dumpf(s, dst_file)

                    # unset route tid 1 dip 1.1.1.1 netmask 24 port dpdk0 net|local
                    self.msgs.append('unset route tid {} dip {} netmask {} port {} {}'.format(self.vrf, self.dip, self.netmask, self.port, self.type))
                    vfw_send(self.msgs)

            if self.proto == 'v6':
                ret = vfwcfg.route_del(s, self.vrf, self.proto, dip = self.dip, prefix_len = self.prefix_len, port = self.port, type = self.type)
                if ret:
                    vfwcfg.dumpf(s, dst_file)

                    # unset route6 tid 1 dip 1::1 prefix-len 96 port dpdk0 net|local
                    self.msgs.append('unset route6 tid {} dip {} prefix-len {} port {} {}'.format(self.vrf, self.dip, self.prefix_len, self.port, self.type))
                    vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = RouteCfgApi.make_response(self.return_string, 200)
            #return jsonify(status = self.return_string)
            return jsonify(result)

        if url[-1] == 'query':
            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
                #self.return_string = 'Bad Request'
                #response = RouteCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            result['data'] = vfwcfg.route_get_all(s, self.vrf, self.proto)
            return jsonify(result)

class VxlanCfg(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(trim = True, bundle_errors = True)
        self.reqparse.add_argument('vni',    type = str, default = '', location = 'json')
        self.reqparse.add_argument('proto',  type = str, default = '', location = 'json')
        self.reqparse.add_argument('sip',    type = str, default = '', location = 'json')
        self.reqparse.add_argument('rip',    type = str, default = '', location = 'json')

        self.args = self.reqparse.parse_args(strict = True)
        self.vni       = self.args['vni'].strip()
        self.proto     = self.args['proto'].strip()
        self.sip       = self.args['sip'].strip()
        self.rip       = self.args['rip'].strip()
        self.msgs      = list()

    # create vxlan
    def post(self):
        result = dict()
        result['code'] = '200'
        result['msg'] = 'OK'
        result['data'] = None

        global conf_obj
        if conf_obj:
            s = conf_obj
        else:
            conf_obj = vfwcfg.loadf(src_file)
            s = conf_obj

        url = request.path.strip('/ ').rsplit('/', 1)
        if url[-1] == 'add':
            if not self.vni or not self.proto or not self.sip or not self.rip:
                #self.return_string = 'Bad Request'
                #response = VxlanCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if  vfwcfg.vxlan_is_exist(s, self.vni):
                #self.return_string = 'Bad Request'
                #response = VxlanCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            vfwcfg.vxlan_add(s, vni=self.vni, proto=self.proto, sip=self.sip, rip=self.rip)
            vfwcfg.dumpf(s, dst_file)

            if self.proto == 'v4':
                for r in self.rip.split(','):
                    # set vxlan tunnel vni 1 v4 sip 1.1.1.1 rip 1.1.1.2
                    self.msgs.append('set vxlan tunnel vni {} v4 sip {} rip {}'.format(self.vni, self.sip, r.strip()))

            if self.proto == 'v6':
                for r in self.rip.split(','):
                    # set vxlan tunnel vni 1 v6 sip 1::1 rip 1::2
                    self.msgs.append('set vxlan tunnel vni {} v6 sip {} rip {}'.format(self.vni, self.sip, r.strip()))

            vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = VxlanCfgApi.make_response(self.return_string, 200)
            #return jsonify(status = self.return_string)
            return jsonify(result)

        # delete vxlan
        # def delete(self):
        if url[-1] == 'delete':
            if not self.vni:
                #self.return_string = 'Bad Request'
                #response = VxlanCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            ret = vfwcfg.vxlan_del(s, self.vni)
            if ret:
                vfwcfg.dumpf(s, dst_file)
                #  unset vxlan tunnel vni 1
                self.msgs.append('unset vxlan tunnel vni {}'.format(self.vni))
                vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = VxlanCfgApi.make_response(self.return_string, 200)
            #return jsonify(status = self.return_string)
            return jsonify(result)

        if url[-1] == 'query':
            result['data'] = vfwcfg.vxlan_get_all(s, self.vni)
            return jsonify(result)

class ArpCfg(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(trim = True, bundle_errors = True)
        self.reqparse.add_argument('uid',    type = str, default = '', location = 'json', required=True)
        self.reqparse.add_argument('proto',  type = str, default = '', location = 'json')
        self.reqparse.add_argument('ip',     type = str, default = '', location = 'json')
        self.reqparse.add_argument('mac',    type = str, default = '', location = 'json')

        self.args = self.reqparse.parse_args(strict = True)
        self.vrf       = self.args['uid'].strip()
        self.proto     = self.args['proto'].strip()
        self.ip        = self.args['ip'].strip()
        self.mac       = self.args['mac'].strip()
        self.msgs      = list()

    # create arp
    def post(self):
        result = dict()
        result['code'] = '200'
        result['msg'] = 'OK'
        result['data'] = None

        global conf_obj
        if conf_obj:
            s = conf_obj
        else:
            conf_obj = vfwcfg.loadf(src_file)
            s = conf_obj

        url = request.path.strip('/ ').rsplit('/', 1)
        if url[-1] == 'add':
            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)

            if not self.vrf or not self.proto or not self.ip or not self.mac:
                #self.return_string = 'Bad Request'
                #response = ArpCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if vfwcfg.arp_is_exist(s, self.vrf, self.proto, ip=self.ip, mac=self.mac):
                #self.return_string = 'Bad Request'
                #response = ArpCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            vfwcfg.arp_add(s, self.vrf, self.proto, ip=self.ip, mac=self.mac)
            vfwcfg.dumpf(s, dst_file)

            if self.proto == 'v4':
                # set neigh tid 1 dip 1.1.1.1 mac xxx 
                self.msgs.append('set neigh tid {} dip {} mac {}'.format(self.vrf, self.ip, self.mac))

            if self.proto == 'v6':
                # set neigh tid 1 dip 1::1 mac xxx 
                self.msgs.append('set neigh tid {} dip {} mac {}'.format(self.vrf, self.ip, self.mac))

            vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = ArpCfgApi.make_response(self.return_string, 200)
            #return jsonify(status = self.return_string)
            return jsonify(result)

        # delete arp
        # def delete(self):
        if url[-1] == 'delete':
            if not self.vrf:
                #self.return_string = 'Bad Request'
                #response = ArpCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if self.proto and self.proto != 'v4' and self.proto != 'v6':
                #self.return_string = 'Bad Request'
                #response = ArpCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            vfwcfg.dumpf(s, dst_file)

            if not self.vrf:
                #self.return_string = 'Bad Request'
                #response = ArpCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if self.ip:
                #unset neigh tid 1 dip 1.1.1.1 
                vfwcfg.arp_del(s, self.vrf, self.proto, ip=self.ip)
                self.msgs.append('unset neigh tid {} dip {}'.format(self.vrf, self.ip))
            else:
                #unset neigh tid 1
                vfwcfg.arp_del_all(s, self.vrf)
                self.msgs.append('unset neigh tid {}'.format(self.vrf))

            vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = ArpCfgApi.make_response(self.return_string, 200)
            #return jsonify(status = self.return_string)
            return jsonify(result)

        if url[-1] == 'query':
            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            result['data'] = vfwcfg.arp_get_all(s, self.vrf, self.proto)
            return jsonify(result)


class VrfBindCfg(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(trim = True, bundle_errors = True)
        self.reqparse.add_argument('uid',    type = str, default = '', location = 'json', required=True)
        self.reqparse.add_argument('vni',    type = str, default = '', location = 'json')
        self.reqparse.add_argument('ip',     type = str, default = '', location = 'json')
        self.reqparse.add_argument('ip6',    type = str, default = '', location = 'json')
        self.reqparse.add_argument('port',   type = str, default = '', location = 'json')

        self.args = self.reqparse.parse_args(strict = True)
        self.vrf       = self.args['uid'].strip()
        self.vni       = self.args['vni'].strip()
        self.ip        = self.args['ip'].strip()
        self.ip6       = self.args['ip6'].strip()
        self.port      = self.args['port'].strip()
        self.msgs      = list()

    # modify vrf bind info
    def post(self):
        result = dict()
        result['code'] = '200'
        result['msg'] = 'OK'
        result['data'] = None

        global conf_obj
        if conf_obj:
            s = conf_obj
        else:
            conf_obj = vfwcfg.loadf(src_file)
            s = conf_obj

        url = request.path.strip('/ ').rsplit('/', 1)
        if url[-1] == 'update':
            if not self.vrf:
                #self.return_string = 'Bad Request'
                #response = VrfBindCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            if not self.vrf:
                #self.return_string = 'Bad Request'
                #response = VrfBindCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            vfwcfg.vrf_bind_set(s, self.vrf, vni=self.vni, ip=self.ip, ip6=self.ip6)
            vfwcfg.dumpf(s, dst_file)

            # ignore port
            # vfwcfg.vrf_bind_set(s, self.vrf, vni=self.vni, ip=self.ip, ip6=self.ip6, port=self.port)

            for i in self.vni.split(','):
                # set vrf_l3 vid 1 vni 1
                self.msgs.append('set vrf_l3 vid {} vni {}'.format(self.vrf, i.strip()))

            for i in self.ip.split(','):
                # set vrf_l3 vid 1 ip v4 1.1.1.1
                self.msgs.append('set vrf_l3 vid {} ip v4 {}'.format(self.vrf, i.strip()))

            for i in self.ip6.split(','):
                # set vrf_l3 vid 1 ip v6 1::1
                self.msgs.append('set vrf_l3 vid {} ip v6 {}'.format(self.vrf, i.strip()))

            vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = VrfBindCfgApi.make_response(self.return_string, 200)
            #return jsonify(status = self.return_string)
            return jsonify(result)

        # delete vrf bind info
        # def delete(self):
        if url[-1] == 'delete':
            if not self.vrf:
                #self.return_string = 'Bad Request'
                #response = VrfBindCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            if not self.vrf:
                #self.return_string = 'Bad Request'
                #response = VrfBindCfgApi.make_response(self.return_string, 400)
                #return response
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            if not self.vni and not self.ip and not self.ip6 and not self.port:
                vfwcfg.vrf_bind_del_all(s, self.vrf)
                vfwcfg.dumpf(s, dst_file)

                self.msgs.append('unset vrf_l3 vid {}'.format(self.vrf))
                vfw_send(self.msgs)

                #self.return_string = 'OK'
                #response = VrfBindCfgApi.make_response(self.return_string, 200)
                #return jsonify(status = self.return_string)
                return jsonify(result)

            vfwcfg.vrf_bind_del(s, self.vrf, vni=self.vni, ip=self.ip, ip6=self.ip6, port=self.port)
            vfwcfg.dumpf(s, dst_file)

            for i in self.vni.split(','):
                # unset vrf_l3 vid 1 vni 1
                self.msgs.append('unset vrf_l3 vid {} vni {}'.format(self.vrf, i.strip()))

            for i in self.ip.split(','):
                # unset vrf_l3 vid 1 ip v4 1.1.1.1
                self.msgs.append('unset vrf_l3 vid {} ip v4 {}'.format(self.vrf, i.strip()))

            for i in self.ip6.split(','):
                # unset vrf_l3 vid 1 ip v6 1::1
                self.msgs.append('unset vrf_l3 vid {} ip v6 {}'.format(self.vrf, i.strip()))

            vfw_send(self.msgs)

            #self.return_string = 'OK'
            #response = VrfBindCfgApi.make_response(self.return_string, 200)
            #return jsonify(status = self.return_string)
            return jsonify(result)

        if url[-1] == 'query':
            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            result['data'] = vfwcfg.vrf_bind_get(s, self.vrf)
            return jsonify(result)

class FlowSwitchCfg(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(trim = True, bundle_errors = True)
        self.reqparse.add_argument('arp', type = str, default = '', location = 'json')

        self.args  = self.reqparse.parse_args(strict = True)
        self.arp   = self.args['arp'].strip()
        self.msgs  = list()

    def post(self):
        result = dict()
        result['code'] = '200'
        result['msg'] = 'OK'
        result['data'] = None

        global conf_obj
        if conf_obj:
            s = conf_obj
        else:
            conf_obj = vfwcfg.loadf(src_file)
            s = conf_obj

        url = request.path.strip('/ ').rsplit('/', 1)
        if url[-1] == 'update':
            switch_list = ['enable', 'disable']
            if not self.arp in switch_list:
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return jsonify(result)

            vfwcfg.flow_switch_set(s, arp=self.arp)
            vfwcfg.dumpf(s, dst_file)

            # set switch arp enable | disable
            self.msgs.append('set switch arp {}'.format(self.arp))
            vfw_send(self.msgs)

            return jsonify(result)

    def get(self):
        global conf_obj
        if conf_obj:
            s = conf_obj
        else:
            conf_obj = vfwcfg.loadf(src_file)
            s = conf_obj

        result = dict()
        result['code'] = '200'
        result['msg'] = 'OK'

        url = request.path.strip('/ ').rsplit('/', 1)
        if url[-1] == 'query':
            result['data'] = vfwcfg.flow_switch_get(s)
            return jsonify(result)

class RateLimitCfg(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(trim = True, bundle_errors = True)
        self.reqparse.add_argument('uid',      type = str, default = '', location = 'json', required=True)
        self.reqparse.add_argument('bandwith', type = str, default = '', location = 'json')

        self.args      = self.reqparse.parse_args(strict = True)
        self.vrf       = self.args['uid'].strip()
        self.bandwith  = self.args['bandwith'].strip()
        self.msgs      = list()

    def post(self):
        result = dict()
        result['code'] = '200'
        result['msg'] = 'OK'
        result['data'] = None

        global conf_obj
        if conf_obj:
            s = conf_obj
        else:
            conf_obj = vfwcfg.loadf(src_file)
            s = conf_obj

        url = request.path.strip('/ ').rsplit('/', 1)
        if url[-1] == 'update':
            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
                result['code'] = '400'
                result['msg'] = 'Invalid parameter'
                return result

            vfwcfg.rate_limit_set(s, self.vrf, bandwith=self.bandwith)
            vfwcfg.dumpf(s, dst_file)

            # set rate-limiting flow-id xxx bandwith 100
            self.msgs.append('set rate-limiting flow-id {} bandwith {}'.format(self.vrf, self.bandwith))
            vfw_send(self.msgs)

            return jsonify(result)

        if url[-1] == 'query':
            # convert uuid to id
            self.vrf = vfwcfg.uid_get(s, self.vrf)
            if not self.vrf or not vfwcfg.vrf_is_exist(s, self.vrf):
                result['code'] = '404'
                result['msg'] = 'Not Found'
                return result

            print('vrf {}'.format(self.vrf))
            result['data'] = vfwcfg.rate_limit_get(s, self.vrf)
            return jsonify(result)

class VrrpCfg(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser(trim = True, bundle_errors = True)
        self.reqparse.add_argument('status',        type = str, default = '', location = 'json', choices = ('enable', 'disable'))
        self.reqparse.add_argument('interface',     type = str, default = '', location = 'json')
        self.reqparse.add_argument('unicast_peer',  type = str, default = '', location = 'json')
        self.reqparse.add_argument('vrid',          type = str, default = '', location = 'json')
        self.reqparse.add_argument('priority',      type = str, default = '', location = 'json')
        self.reqparse.add_argument('interval',      type = str, default = '', location = 'json')
        self.reqparse.add_argument('vip_proto',     type = str, default = '', location = 'json', choices = ('v4', 'v6'))
        self.reqparse.add_argument('vip',           type = str, default = '', location = 'json')
        self.reqparse.add_argument('preempt_delay', type = str, default = '', location = 'json')

        self.args          = self.reqparse.parse_args(strict = True)
        self.status        = self.args['status'].strip()
        self.interface     = self.args['interface'].strip()
        self.unicast_peer  = self.args['unicast_peer'].strip()
        self.vrid          = self.args['vrid'].strip()
        self.priority      = self.args['priority'].strip()
        self.interval      = self.args['interval'].strip()
        self.vip_proto     = self.args['vip_proto'].strip()
        self.vip           = self.args['vip'].strip()
        self.preempt_delay = self.args['preempt_delay'].strip()
        self.msgs = list()

    def post(self):
        result = dict()
        result['code'] = '200'
        result['msg'] = 'OK'
        result['data'] = None

        global conf_obj
        if conf_obj:
            s = conf_obj
        else:
            conf_obj = vfwcfg.loadf(src_file)
            s = conf_obj

        url = request.path.strip('/ ').rsplit('/', 1)
        if url[-1] == 'update':
            if self.vip_proto == 'v4':
                vfwcfg.vrrp_cfg_set(s, vrrp_enable=self.status, vrrp_interface=self.interface, vrrp_unicast_peer=self.unicast_peer,
                        vrrp_virtual_router_id=self.vrid, vrrp_priority=self.priority, vrrp_advert_int=self.interval,
                        vrrp_virtual_ipaddress=self.vip, vrrp_preempt_delay=self.preempt_delay)
            else:
                vfwcfg.vrrp_cfg_set(s, vrrp_enable=self.status, vrrp_interface=self.interface, vrrp_unicast_peer=self.unicast_peer,
                        vrrp_virtual_router_id=self.vrid, vrrp_priority=self.priority, vrrp_advert_int=self.interval,
                        vrrp_virtual_ipv6=self.vip, vrrp_preempt_delay=self.preempt_delay)

            vfwcfg.dumpf(s, dst_file)

            if self.status:
                self.msgs.append('set vrrp {}'.format(self.status))

            if self.interface:
                self.msgs.append('set vrrp interface {}'.format(self.interface))

            if self.unicast_peer:
                self.msgs.append('set vrrp unicast-peer {}'.format(self.unicast_peer))

            if self.vrid:
                self.msgs.append('set vrrp vrid {}'.format(self.vrid))

            if self.priority:
                self.msgs.append('set vrrp priority {}'.format(self.priority))

            if self.interval:
                self.msgs.append('set vrrp timer advertise {}'.format(self.interval))

            if self.vip_proto == 'v4':
                self.msgs.append('set vrrp virtual-ip {}'.format(self.vip))

            if self.vip_proto == 'v6':
                self.msgs.append('set vrrp virtual-ipv6 {}'.format(self.vip))

            if self.preempt_delay:
                self.msgs.append('set vrrp preempt-mode delay {}'.format(self.preempt_delay))

            vfw_send(self.msgs)

            return jsonify(result)

    def get(self):
        result = dict()
        result['code'] = '200'
        result['msg'] = 'OK'
        result['data'] = None

        global conf_obj
        if conf_obj:
            s = conf_obj
        else:
            conf_obj = vfwcfg.loadf(src_file)
            s = conf_obj

        url = request.path.strip('/ ').rsplit('/', 1)
        if url[-1] == 'query':
            result['data'] = vfwcfg.vrrp_cfg_get(s)
            return jsonify(result)

# Not Support
# SessionCfgApi.add_resource(SessionCfg,                     '/vfw/api/v1/system/session')
# AspfPolicyCfgApi.add_resource(AspfPolicyCfg,               '/vfw/api/v1/system/aspfpolicy')

VrfCfgApi.add_resource(VrfCfg,                          '/vfw/api/v1/system/vrf/query',
                                                        '/vfw/api/v1/system/vrf/add',
                                                        '/vfw/api/v1/system/vrf/delete')

SecPolicySubnetCfgApi.add_resource(SecPolicySubnetCfg,  '/vfw/api/v1/system/secpolicy/subnet/query',
                                                        '/vfw/api/v1/system/secpolicy/subnet/add',
                                                        '/vfw/api/v1/system/secpolicy/subnet/delete')

SecPolicyInCfgApi.add_resource(SecPolicyInCfg,          '/vfw/api/v1/system/secpolicyin/query',
                                                        '/vfw/api/v1/system/secpolicyin/add',
                                                        '/vfw/api/v1/system/secpolicyin/delete',
                                                        '/vfw/api/v1/system/secpolicyin/update')

SecPolicyOutCfgApi.add_resource(SecPolicyOutCfg,        '/vfw/api/v1/system/secpolicyout/query',
                                                        '/vfw/api/v1/system/secpolicyout/add',
                                                        '/vfw/api/v1/system/secpolicyout/delete',
                                                        '/vfw/api/v1/system/secpolicyout/update')

SecPolicyInOrderApi.add_resource(SecPolicyInOrderCfg,   '/vfw/api/v1/system/secpolicyin/order/update')

SecPolicyOutOrderApi.add_resource(SecPolicyOutOrderCfg, '/vfw/api/v1/system/secpolicyout/order/update')

IpsCfgApi.add_resource(IpsCfg,                          '/vfw/api/v1/system/ipscfg/query',
                                                        '/vfw/api/v1/system/ipscfg/update')

IpsRuleCfgApi.add_resource(IpsRuleCfg,                  '/vfw/api/v1/system/ipsrule/query',
                                                        '/vfw/api/v1/system/ipsrule/update')

VlanPortCfgApi.add_resource(VlanPortCfg,                '/vfw/api/v1/system/vlan-port/query',
                                                        '/vfw/api/v1/system/vlan-port/add',
                                                        '/vfw/api/v1/system/vlan-port/delete')

PortIPCfgApi.add_resource(PortIPCfg,                    '/vfw/api/v1/system/portip/query',
                                                        '/vfw/api/v1/system/portip/update',
                                                        '/vfw/api/v1/system/portip/delete')

RouteCfgApi.add_resource(RouteCfg,                      '/vfw/api/v1/system/route/query',
                                                        '/vfw/api/v1/system/route/add',
                                                        '/vfw/api/v1/system/route/delete')

VxlanCfgApi.add_resource(VxlanCfg,                      '/vfw/api/v1/system/vxlan/query',
                                                        '/vfw/api/v1/system/vxlan/add',
                                                        '/vfw/api/v1/system/vxlan/delete')

ArpCfgApi.add_resource(ArpCfg,                          '/vfw/api/v1/system/arp/query',
                                                        '/vfw/api/v1/system/arp/add',
                                                        '/vfw/api/v1/system/arp/delete')

VrfBindCfgApi.add_resource(VrfBindCfg,                  '/vfw/api/v1/system/vrf-bind/query',
                                                        '/vfw/api/v1/system/vrf-bind/update',
                                                        '/vfw/api/v1/system/vrf-bind/delete')

FlowSwitchCfgApi.add_resource(FlowSwitchCfg,            '/vfw/api/v1/system/flow-switch/query',
                                                        '/vfw/api/v1/system/flow-switch/update',
                                                        '/vfw/api/v1/system/flow-switch/delete')

RateLimitCfgApi.add_resource(RateLimitCfg,              '/vfw/api/v1/system/rate-limit/query',
                                                        '/vfw/api/v1/system/rate-limit/update')

VrrpCfgApi.add_resource(VrrpCfg,                        '/vfw/api/v1/system/vrrp/query',
                                                        '/vfw/api/v1/system/vrrp/update')


def signal_func(sig, frame):
    #pdb.set_trace()
    global conf_obj
    if conf_obj:
        s = conf_obj
    else:
        conf_obj = vfwcfg.loadf(src_file)
        s = conf_obj

    vfwcfg.ips_policy_delete_all(s)
    vfwcfg.dumpf(s, dst_file)

if __name__ == '__main__':
    try:
        if len(sys.argv) < 3:
            output.error('Please input ip and port.')
            sys.exit(1)

        ips_init()

        conf_obj = vfwcfg.loadf(src_file)
        vfwcfg.fw_init(conf_obj)

        signal.signal(signal.SIGUSR1, signal_func)
        if sys.argv[1]:
            output.info('fw-agent running.')
            app.run(host = sys.argv[1], port = sys.argv[2], debug = False, threaded=False)
        else:
            app.run(host = '0.0.0.0', port = '5000', debug = False, threaded=False)
    except Exception as e:
        output.exception('{} run error {}.'.format(__name__, e))

