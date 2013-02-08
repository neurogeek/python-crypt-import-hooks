#!/usr/bin/env python
#encoding: utf-8

from __future__ import print_function
import os
import sys
from subprocess import STDOUT, Popen

#Add dist to PYTHONPATH
sys.path.append("/".join([os.path.abspath("."), "dist"]))

#We run our converter to cipher the module
CryptConv = "dist/CryptConv"
p = Popen(" ".join([CryptConv, "test_script.py", "EncModule.pye"]), shell=True)
p.wait()

#Now, for the Actual Test
print("Starting Test. Importing CryptImpHook", end="\n")
from CryptImpHook import CryptImpHook
print("Adding CryptImpHook to meta_path", end="\n")
sys.meta_path.append(CryptImpHook())
print("Import class C from EncModule", end="\n")


#Now lets import our Module
import EncModule
EncModule.C(1, 2, 3)
