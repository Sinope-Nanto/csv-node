#!/usr/bin/python3
#
# Copyright (c) 2023 ISCAS TCA @ by TCWG vonsky
#

import json
import os
import subprocess
import json
import time


global_invalidchipid = "000000000000000"
global_invalidcpumodel = "unknown"

def run_command(command):  
   try:  
       output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True, text=True)  
       return output  
   except subprocess.CalledProcessError as e:  
       return f"Command error: {e.output.decode('utf-8')}"

def find_specific_string(multiline_string, target_string):  
   lines = multiline_string.split('\n')  
   for line in lines:  
       if target_string in line:  
           return line  
   return None

def get_chipid():
    mycommand = "/opt/hygon/bin/hag general get_id"
    myresult = run_command(mycommand)
    global global_invalidchipid 
    myret = global_invalidchipid
    #print(type(myresult))
    #print(len(myresult.split('\n')))
    #print(myresult)
    if "Command error" in myresult:
        print("error to execute get_chipid: {} ".format(myresult))
    else: # parse the output result to get real chipid
        target_line = find_specific_string(myresult, "chip id is")
        #print(target_line)
        if target_line is None:
            print("invalid output for get_chipid: {}".format(myresult))
        else:
            myret = target_line.replace("\n", "")[11:].strip().replace("\u0000", "")
    return myret

def get_cpumode():
    mycommand = "lscpu |grep \"Model name\""
    myresult = run_command(mycommand)
    global global_invalidcpumodel
    myret = global_invalidcpumodel
    if "Hygon C86" in myresult:
        index = myresult.find("Hygon C86")
        myret = myresult.replace("\n", "")[index:]

    return myret

def get_hostname():
    mycommand = "hostname"
    myresult = run_command(mycommand)
    return myresult.replace("\n", "")

def get_osinfo():
    mycommand = "lsb_release -d"
    myresult = run_command(mycommand)
    myret = "unknown os"
    if "Ubuntu" in myresult:
        index = myresult.find("Ubuntu")
        myret = myresult.replace("\n", "")[index:]

    return myret

def get_kernelinfo():
    mycommand = "cat /proc/version"
    myresult = run_command(mycommand)
    myret = "unknown kernel"
    if "Linux version" in myresult:
        myret = myresult.replace("\n", "")

    return myret

def get_BIOSVersion():
    mycommand = "dmidecode -s bios-version"
    myresult = run_command(mycommand)
    return myresult.replace("\n", "")

def get_platfirmware():
    mycommand = "/opt/hygon/bin/hag csv platform_status"
    myresult = run_command(mycommand)

    myret = {}
    
    lines = myresult.split('\n')
    for line in lines:
        if ":" in line:
            myline = line.replace("\n", "").split(':')
            if len(myline) == 2:
                mname, mvalue = myline
                myret[mname.strip()] = mvalue.strip()
            else:
                print("invalid line for get_platfirmware: {}".format(line))

    return myret

def gen_platbaseinfo_tojson():
    platinfo = {}
    # current_time = time.time()
    # formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(current_time))
    # platinfo['Time'] = formatted_time

    platinfo['ChipID'] = get_chipid()
    platinfo['host'] = get_hostname()
    platinfo['os'] = get_osinfo()
    # platinfo['Kernel'] = get_kernelinfo()
    platinfo['BIOS'] = get_BIOSVersion()
    platinfo['devinfo'] = get_cpumode()
    platinfo['data'] = get_platfirmware()
    platinfo['type'] = 4

    # output to platinfo.json file
    with open("platinfo.json", "w", encoding="utf-8") as f:
        json.dump(platinfo, f, ensure_ascii=False, indent=4)  


if __name__ == '__main__':
    print("###########Entry get_platbaseinfo.py###################")
    #chipid = get_chipid()
    #print(chipid)

    #ret = get_platfirmware()
    #print(ret)
    gen_platbaseinfo_tojson()

    print("###########Exit get_platbaseinfo.py###################")
