#!/usr/bin/python3
#
# Copyright (c) 2023 ISCAS TCA @ by TCWG vonsky
#

import json
import os
import subprocess
import json
import time
import requests
import socket
import uuid

global_invalidchipid = "000000000000000"
global_invalidcpumodel = "unknown"

def invert_endian(buf, len):
    for i in range(len >> 1):
        tmp = buf[i]
        buf[i] = buf[len - i -1]
        buf[len - i -1] =  tmp

def get_mac_address():
    mac=uuid.UUID(int = uuid.getnode()).hex[-12:].upper()
    return ":".join([mac[e:e+2] for e in range(0,11,2)])

def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()

    return ip

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
        myresult = myresult.split(' ')
        myret = myresult[0] + ' ' + myresult[1] + ' ' + myresult[2]

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
                myret[mname.strip().replace(' ','_').lower()] = mvalue.strip()
            else:
                print("invalid line for get_platfirmware: {}".format(line))

    return myret

def get_hex_str(file_name):
    with open(file_name,"rb") as f:
        abytes = f.read()
        return abytes.hex()
    
def gen_platbaseinfo_tojson():
    platinfo = {}
    with open('network_config.json', 'r') as f:
        network_config = json.load(f)

    platinfo['port'] = network_config['listen_port']
    platinfo['host'] = get_hostname()
    # platinfo['os'] = get_osinfo()
    platinfo['os'] = get_kernelinfo()
    platinfo['name'] = get_BIOSVersion()
    platinfo['devinfo'] = get_cpumode()
    platinfo['data'] = {}
    platinfo['data']['tcb_info'] = get_platfirmware()
    platinfo['data']['chip_id'] = get_chipid()
    platinfo['type'] = 4
    
    cek_str = get_hex_str("cek.cert")
    platinfo['data']['cek_cert'] = cek_str
    platinfo['data']['cek_cert_len'] = len(cek_str)

    hrk_str = get_hex_str("hrk.cert")
    platinfo['data']['hrk_cert'] = hrk_str
    platinfo['data']['hrk_cert_len'] = len(hrk_str)

    hsk_str = get_hex_str("hsk.cert")
    platinfo['data']['hsk_cert'] = hsk_str
    platinfo['data']['hsk_cert_len'] = len(hsk_str)

    pdh_str = get_hex_str("pdh.cert")
    platinfo['data']['pdh_cert'] = pdh_str
    platinfo['data']['pdh_cert_len'] = len(pdh_str)

    pek_str = get_hex_str("pek.cert")
    platinfo['data']['pek_cert'] = pek_str
    platinfo['data']['pek_cert_len'] = len(pek_str)

    PUB_X_POS = 20 << 1
    PUB_Y_POS = 92 << 1
    x_bin = bytearray.fromhex(pek_str[PUB_X_POS:(PUB_X_POS + 64)])
    y_bin = bytearray.fromhex(pek_str[PUB_Y_POS:(PUB_Y_POS + 64)])
    invert_endian(x_bin, 32)
    invert_endian(y_bin, 32)

    platinfo['ak_pubkey'] = {}
    platinfo['ak_pubkey']["x_size"] = 64
    platinfo['ak_pubkey']["y_size"] = 64
    platinfo['ak_pubkey']["x_point"] = x_bin.hex()
    platinfo['ak_pubkey']["y_point"] = y_bin.hex()

    platinfo['ip'] = get_host_ip()
    platinfo['manufacture'] = platinfo['devinfo'].split(' ')[0]
    platinfo['mac'] = get_mac_address()
    platinfo['area'] = run_command('curl https://ifconfig.net/country-iso').split('\n')[-2]

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
