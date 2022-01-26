#!/usr/bin/env python3

import os
import time
import vfwcfg

src_file = "../etc/dpvs.conf"
dst_file = "./tmp.conf"

if '__main__' == __name__:
    try:
        print('init 1 {}'.format(int(time.time())))
        s = vfwcfg.loadf(src_file)
        print('init 2 {}'.format(int(time.time())))
        vfwcfg.dumpf(s, dst_file)
        print('init 3 {}'.format(int(time.time())))
    except Exception as e:
        print("error:{}".format(e))

