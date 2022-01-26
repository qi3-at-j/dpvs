#!/bin/sh

########################################
# cur_work_root_dir:If there is not
# enough space, modify cur_work_root_dir
# value or modify the directory as a
# pass-through when executing the script(
# For example:./makePack.sh /opt).

cur_work_root_dir=/tmp

# need_free_size(KB):It needs to be larger
# than the size of the package and you
# can modify its value to guarantee this
# requirement.

# 500MB
need_free_size=512000
########################################

cur_dir=$(pwd)
make_conf_file=pack.conf
pack_dir_name=fw_pack

clear_work_dir()
{
	if [ -d "$cur_work_dir" ]; then
		rm -rf $cur_work_dir
	fi
}

check_env()
{
	echo "check env..."

	if [ -n "$1" ]; then
		cur_work_root_dir=$1
	fi

	cur_work_dir=$cur_work_root_dir/$pack_dir_name
	echo "make pack dir is $cur_work_dir"

	while :
	do
		final_ch=${cur_work_root_dir: -1}
		if [ "$final_ch" = "/" ]; then		
			cur_work_root_dir=$(echo ${cur_work_root_dir%?})
		else
			break
		fi
	done

	if [ ! -d "$cur_work_root_dir" ]; then
		echo "$cur_work_root_dir does not exist!!!"
		return 1
	fi

	free_size=$(df -k | grep "${cur_work_root_dir}$" | awk  -F ' ' '{print $4}')
	if [ -z "$free_size" ];then
		free_size=$(df -k | grep "/$" | awk  -F ' ' '{print $4}')
	fi

	if [ -z "$free_size" ];then
		free_size=0
	fi

	if [ "$free_size" -lt "$need_free_size" ]; then
		echo "There is not enough space in $cur_work_root_dir"
		echo "Need ${need_free_size}KB,but $cur_work_root_dir only have ${free_size}KB"
		return 1
	fi

	echo "check env success"
	return 0
}

put_files()
{
	echo "put files..."

	if [ ! -f "$cur_dir/$make_conf_file" ]; then
		echo "$make_conf_file does not exist!!!"
		return 1
	fi

	cur_kernel=$(uname -r)

	while read line || [[ -n ${line} ]]
	do
		([[ $line =~ ^#.* ]] || [[ $line = "" ]]) && continue
		files=$(echo $line | awk -F ";" '{print $1}')
		dir=$(echo $line | awk -F ";" '{print $2}')
		dir=$(eval echo $dir)
		if [[ $dir =~ ^/.* ]]; then
			dir=$cur_work_dir$dir
		else
			dir=$cur_work_dir/$dir
		fi
		mkdir -p $dir
		\cp -rfd $files $dir
		if [ "$?" != "0" ]; then
			echo "$files => $dir err!!!"
			return 1
		fi
		echo "$files => $dir success"
	done < $cur_dir/$make_conf_file

	echo "put files success"
	return 0
}

tar_pack()
{
	#DATE=$(date +%Y-%m-%d-%H-%M-%S)
	DATE=$(date +%s)
	if [ "$?" != "0" ]; then
		echo "get date failed!!!"
		return 1
	fi
	pack_name=${pack_dir_name}_${DATE}_${cur_kernel}.tgz
	echo "Start make pack,please wait..."
	echo "pack_name:$pack_name"
	pack_name=$cur_dir/$pack_name
	cd $cur_work_root_dir
	tar zcf $pack_name $pack_dir_name
	if [ "$?" != "0" ]; then
		if [ -n "$pack_name" ]; then
			rm -f $pack_name
		fi
		cd $cur_dir
		return 1
	fi
	cd $cur_dir
	return 0
}

check_env $1
if [ "$?" != "0" ]; then
	echo "check_env failed!!!"
	echo "make fw pack failed!!!"
	exit 1
fi

clear_work_dir

put_files
if [ "$?" != "0" ]; then
	clear_work_dir
	echo "put_files failed!!!"
	echo "make fw pack failed!!!"
	exit 1
fi

tar_pack
if [ "$?" != "0" ]; then
	clear_work_dir
	echo "tar_pack failed!!!"
	echo "make fw pack failed!!!"
	exit 1
fi

#clear_work_dir

echo "make fw pack success"

