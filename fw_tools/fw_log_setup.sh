#!/bin/bash

if [[ $# -lt 2 ]]; then
    echo "arg error.\n"
    exit 1
fi

#echo "arg($#) $1:$2"

SYSLOG_IP=$1
PORT=$2

ver=$(ps -ef | awk '{print $8}' | grep syslog)

#echo $ver

if [[ "$ver" == *rsyslog* ]]; then
    r2=$(grep -c "$SYSLOG_IP" /etc/rsyslog.conf)
    if [[ "$r2" == "0" ]]; then
        echo "local0.*    @$SYSLOG_IP:$PORT" >>/etc/rsyslog.conf

        #service rsyslog restart >/dev/null 2>&1
        systemctl restart rsyslog.service >/dev/null 2>&1

        echo "rsyslog restart complete!"
    else
        echo "rsyslog service is normal!"
    fi
elif [[ "$ver" == *syslog-ng* ]]; then
    ng2=$(grep -c "\"$SYSLOG_IP\"" /etc/syslog-ng/syslog-ng.conf)
    if [[ "$ng2" == "0" ]]; then
        echo "destination d_udp_fw { udp(\"$SYSLOG_IP\" port($PORT)); };" >>/etc/syslog-ng/syslog-ng.conf
        echo "filter f_fw { facility(local0) and not filter(f_debug); };" >>/etc/syslog-ng/syslog-ng.conf
        echo "log { source(s_src); filter(f_fw); destination(d_udp_fw); };" >>/etc/syslog-ng/syslog-ng.conf

        #service syslog-ng restart >/dev/null 2>&1
        systemctl restart syslog-ng.service >/dev/null 2>&1

        echo "syslog-ng restart complete!"
    else
        echo "syslog-ng service is normal!"
    fi
elif [[ "$ver" == *syslog* ]]; then
    ed2=$(grep -c "$SYSLOG_IP" /etc/syslog.conf)
    if [[ "$ed2" == "0" ]]; then
        echo "local0.*    @$SYSLOG_IP:$PORT" >>/etc/syslog.conf

        #service syslog restart >/dev/null 2>&1
        systemctl restart syslog.service >/dev/null 2>&1

        echo "syslog restart complete!"
    else
        echo "syslog service is normal!"
    fi
fi
