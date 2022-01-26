#!/bin/sh

cur_work_dir=$(pwd)
cur_kernel=cur
cur_kernel_auto=cur_auto
need_drv_name=vfio-pci

#If do not reserve the management port, please set 0
reserve_management_port=1

cur_sys_dir=$cur_work_dir/sys
cur_conf_dir=$cur_work_dir/
cur_script_dir=$cur_work_dir/
cur_bin_dir=$cur_sys_dir/$cur_kernel/bin
cur_ko_dir=/usr/local
cur_lib_dir=/usr/local/lib64
work_conf_dir=/etc

tmp_file=tmp_res.del
conf_file=dpvs.conf

unset_vfio()
{
	echo 0 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode
	ko_load=$(lsmod | grep $need_drv_name)
	if [ -n "$ko_load" ]; then
		rmmod $need_drv_name
	fi
}

unset_dev()
{
	if [ -f "$tmp_file" ]; then
		rm -f $tmp_file
	fi

	$cur_script_dir/dpdk-devbind.py -s | grep "drv=$need_drv_name" >> $tmp_file
	while read line
	do
		unused_drv=$(echo $line | awk -F "unused=" '{print $2}' | awk '{print $1}')
		dev_id=$(echo $line | awk '{print $1}')
		$cur_script_dir/dpdk-devbind.py --bind=$unused_drv $dev_id
	done < $tmp_file
	rm -f $tmp_file
}

unset_sys_env()
{
	cd $cur_sys_dir
	if [ -L "$cur_kernel_auto" ]; then
		rm -f $cur_kernel_auto
		rm -f $cur_kernel
	fi
	cd - > /dev/null
}

unset_ko()
{
	if [ ! -d "$cur_ko_dir" ]; then
		return 0
	fi

	cd $cur_ko_dir
	for ko_file in $(ls | grep ".ko")
	do
		ko_name=$(echo ${ko_file%.*})
		ko_load=$(lsmod | grep $ko_name)
		if [ -n "$ko_load" ]; then
			rmmod $ko_file
		fi
	done
	cd - > /dev/null
}

unset_conf()
{
	if [ ! -d "$cur_conf_dir" ]; then
		return 0
	fi

	cd $cur_conf_dir
	for conf_name in $(ls . | grep -v "readme")
	do
		rm -f  $work_conf_dir/$conf_name
	done
	cd - > /dev/null
}

set_vfio()
{
	ko_load=$(lsmod | grep $need_drv_name)
	if [ -z "$ko_load" ]; then
		modprobe $need_drv_name
		if [ "$?" != "0" ]; then
			echo "set vfio err!!!Maybe the system doesn't turn on vfio"
			return 1
		fi
	fi
	#modprobe vfio enable_unsafe_noiommu_mode=1
	echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode
	if [ "$?" != "0" ]; then
		echo "Maybe the system doesn't support noiommu mode!!!"
		return 1
	fi
	return 0
}

set_dev()
{
	dev_cnt=$($cur_script_dir/dpdk-devbind.py -s | grep "$need_drv_name" -c)
	up_dev_cnt=$($cur_script_dir/dpdk-devbind.py -s | grep "Active" -c)
	set_dev_cnt=$(cat $cur_conf_dir/$conf_file | grep "<init> device" -c)
	if [ "$reserve_management_port" -ne "0" ]; then
		if [ "$up_dev_cnt" -le "0" ]; then
			echo "No NIC is available for the management port!!!"
			echo "The possible reasons are as follows:"
			echo "1.The NIC is bound to the vfio-pci driver"
			echo "2.The NIC is not up"
			echo "3.The lack of the NIC"
			echo "The solution:"
			echo "Run the clearEnv.sh script, put the NIC up, or add a NIC"
			return 1
		fi
		need_dev_cnt=$(($set_dev_cnt+1))
	else
		need_dev_cnt=$set_dev_cnt
	fi

	if [ -z "$dev_cnt" ] || [ "$dev_cnt" -eq "0" ]; then
		echo "The $need_drv_name NIC cnt is 0!"
		echo "Please add NIC and make sure the NIC can loads the $need_drv_name driver!"
		return 1
	fi

	if [ -z "$set_dev_cnt" ] || [ "$set_dev_cnt" -eq "0" ]; then
		echo "Bind NIC cnt is 0!"
		echo "Please verify the correctness of the $cur_conf_dir/$conf_file"
		return 1
	fi

	if [ "$dev_cnt" -lt "$need_dev_cnt" ]; then
		echo "There are not enough NIC.Need $need_dev_cnt NIC.But have $dev_cnt NIC.Please add NIC!"
		return 1
	fi

	echo "Current NIC cnt:$dev_cnt"
	if [ "$reserve_management_port" -ne "0" ]; then
		echo "Need NIC cnt:$need_dev_cnt = bind NIC cnt:$set_dev_cnt + management NIC cnt:1"
	else
		echo "Need NIC cnt:$need_dev_cnt = bind NIC cnt:$set_dev_cnt"
	fi

	used_drv_cnt=$($cur_script_dir/dpdk-devbind.py -s | grep "drv=$need_drv_name" -c)
	if [ "$used_drv_cnt" -gt "$set_dev_cnt" ]; then
		echo "There are too many NICs bound.Bound NIC cnt:$used_drv_cnt.But need bound NIC cnt:$set_dev_cnt"
		return 1
	elif [ "$used_drv_cnt" -eq "$set_dev_cnt" ]; then
		echo "The binding NIC was completed before."
		return 0
	else
		set_dev_cnt=$(($set_dev_cnt-$used_drv_cnt))
	fi

	if [ -f "$tmp_file" ]; then
		rm -f $tmp_file
	fi

	$cur_script_dir/dpdk-devbind.py -s | grep "$need_drv_name" | grep -v "drv=$need_drv_name" >> $tmp_file
	while read line
	do
		unused_drv=$(echo $line | awk -F "unused=" '{print $2}' | awk '{print $1}')
		used_drv=$(echo $line | awk -F "drv=" '{print $2}' | awk '{print $1}')
		dev_id=$(echo $line | awk '{print $1}')
		dev_name=$(echo $line | awk -F "if=" '{print $2}' | awk '{print $1}')
		dev_st=$(echo $line | awk -F "*" '{print $2}' | awk '{print $1}')
		if [ "$used_drv" != "$need_drv_name" ]; then
			if [ -n "$dev_name" ] && [ "$dev_st" = "Active" ]; then
				if [ "$reserve_management_port" -ne "0" ]; then
					reserve_management_port=0
					continue
				fi
				ifconfig $dev_name down
				ip link set $dev_name down
			fi
			$cur_script_dir/dpdk-devbind.py --bind=$need_drv_name $dev_id
			set_dev_cnt=$(($set_dev_cnt-1))
			if [ "$set_dev_cnt" = "0" ]; then
				break
			fi			
		fi
	done < $tmp_file
	rm -f $tmp_file
	return 0
}

set_hugepages()
{
	mkdir -p /dev/hugepages
	if [ "$?" != "0" ]; then
		echo "mkdir -p /dev/hugepages err!!!"
		return 1
	fi
	
	mountpoint -q /dev/hugepages || mount -t hugetlbfs nodev /dev/hugepages
	if [ "$?" != "0" ]; then
		echo "mount /dev/hugepages err!!!"
		return 1
	fi

	echo 8192 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
	if [ "$?" != "0" ]; then
		echo "set nr_hugepages value err!!!"
		return 1
	fi

	return 0
}

set_sys_env()
{
	cd $cur_sys_dir
	if [ ! -L "$cur_kernel" ] || [ -L "$cur_kernel_auto" ]; then
		rm -f $cur_kernel > /dev/null
		rm -f $cur_kernel_auto > /dev/null
		kv=$(uname -r)
		for dir in $(ls)
		do
			dkv=$(echo ${dir%@*})
			if [ "$kv" = "$dkv" ]; then
				ln -s $dir $cur_kernel_auto
				ln -s $cur_kernel_auto $cur_kernel
				cd - > /dev/null
				return 0
			fi
		done
		echo "Current env kernel version:$kv,match sys dir(./sys/) failed!!!"
		return 1
	fi
	cd - > /dev/null
	return 0
}

set_ko()
{
	if [ ! -d "$cur_ko_dir" ]; then
		echo "$cur_ko_dir does not exist!!!"
		return 1
	fi

	cd $cur_ko_dir
	for ko_file in $(ls | grep ".ko")
	do
		ko_name=$(echo ${ko_file%.*})
		ko_load=$(lsmod | grep $ko_name)
		if [ -z "$ko_load" ]; then
			insmod $ko_file
			if [ "$?" != "0" ]; then
				echo "Load $ko_file err!!!Maybe the ko file does not match the current env kernel version!!!"
				return 1
			fi
		fi
	done
	cd - > /dev/null
	return 0
}

set_conf()
{
	if [ ! -d "$cur_conf_dir" ]; then
		echo "$cur_conf_dir does not exist!!!"
		return 1
	fi

	cd $cur_conf_dir
	for conf_name in $(ls . | grep -v "readme")
	do
		\cp -f $conf_name $work_conf_dir
	done
	cd - > /dev/null
	return 0
}

set_flow_env()
{
	set_vfio
	if [ "$?" != "0" ]; then
		echo "set_vfio err!!!"
		return 1
	fi

	set_dev
	if [ "$?" != "0" ]; then
		echo "set_dev err!!!"
		return 1
	fi

	set_hugepages
	if [ "$?" != "0" ]; then
		echo "set_hugepages err!!!"
		return 1
	fi

	#set_sys_env
	if [ "$?" != "0" ]; then
		echo "set_sys_env err!!!"
		return 1
	fi

	set_ko
	if [ "$?" != "0" ]; then
		echo "set_ko err!!!"
		return 1
	fi

	set_conf
	if [ "$?" != "0" ]; then
		echo "set_conf err!!!"
		return 1
	fi

	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$cur_lib_dir
	return 0
}

unset_flow_env()
{
	unset_dev
	unset_vfio
	unset_ko
	unset_conf
	#unset_sys_env
}

#name=$(basename $0)
name=setEnv.sh
case $1 in
	-s|-set)
		echo "Set flow env start..."
		set_flow_env
		if [ "$?" != "0" ]; then
			echo "Set flow env err!!!"
			exit 1
		fi
		echo "Set flow env success"
		;;
	-u|-unset)
		echo "Unset flow env start..."
		unset_flow_env
		echo "Unset flow env success"
		;;
	*)
		echo "Usage: $name [-s|-set,-u|-unset]"
		exit 1
		;;
esac

