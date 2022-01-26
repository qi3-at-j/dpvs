#!/bin/sh

source ./script/setEnv.sh -s
if [ "$?" == "0" ]; then
	./sys/cur/bin/dpvs
fi

