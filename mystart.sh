#! /bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

#
# Run with "source /path/to/dpdk-setup.sh"
#

#
# Change to DPDK directory ( <this-script's-dir>/.. ), and export it as RTE_SDK

ifconfig ens34 down 
ifconfig ens35 down
echo "ens34 ens35 down"
echo 2048 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
echo "set HugePage"
# Loading Modules to Enable Userspace IO for DPDK 

pwd
# 加载 UIO Framework 内核模块
modprobe uio
# 加载 igb_uio 内核驱动程序模块
insmod igb_uio.ko
cd ${RTE_SDK}
insmod build/kmod/rte_kni.ko carrier=on
modprobe uio_pci_generic
modprobe vfio-pci

lsmod | grep uio
cd ${RTE_SDK}/usertools/
pwd
./dpdk-devbind.py --status-dev net

echo "bind net-------------------------after--------------------"

./dpdk-devbind.py --bind=vfio-pci 0000:0b:00.0
./dpdk-devbind.py --bind=vfio-pci 0000:13:00.0
./dpdk-devbind.py --status-dev net

cd ${RTE_SDK}/examples/helloworld
./build/helloworld

