#!/bin/sh
echo "install start"
yum -y install epel-release
yum -y install gcc libpcap-devel pcre-devel libyaml-devel file-devel \
  zlib-devel jansson-devel nss-devel libcap-ng-devel libnet-devel tar make \
  libnetfilter_queue-devel lua-devel PyYAML libmaxminddb-devel \
  lz4-devel automake autoconf libtool
cd ..

if [ -d "cty-suricata" ]; then
  rm -rf cty-suricata
fi

git clone git@gitlab.engineering.ctyun.cn:vfw/cty-suricata.git -b apr01
cd cty-suricata
if [ ! -d "$HOME/.rustup" ]; then
  tar -xvf rustup.tar.gz
  mv .rustup $HOME/.rustup
fi

if [ ! -d "$HOME/.cargo" ]; then
  tar -xvf cargo.tar.gz
  mv .cargo $HOME/.cargo
fi
source "$HOME/.cargo/env"
export RUSTUP_TOOLCHAIN=1.52.0
cd suricata-6.0.2
autoreconf -ivf
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --enable-nfqueue --enable-lua --enable-geoip
make -j4
make install
make install-conf

cd ..

if [ ! -d "/etc/suricata/rules" ]; then
  mkdir /etc/suricata/rules
fi

if [ -f "/etc/suricata/rules/suricata" ]; then
  rm /etc/suricata/rules/suricata.rules
fi

cp ips.rules /etc/suricata/rules/
cp apr.rules /etc/suricata/rules/

echo "install complete"

