#!/usr/bin/env python

import os

class portscans():
    def pingSweep(self):
        print("#"*92)
        print("\t\tPING SWEEP of target addresses\t\t")
        print("\t\tCheck the file 'alive.ip' for all the alive hosts\t\t")
        print("#"*92)
    #    os.system('nmap -iL targets.ip -sP -PE -oA scans/PingSweep --excludefile exclude.ip -n --open')
        os.system('nmap -sn -PE -iL targets.ip -PS3,7,9,13,17,19,21-23,25-26,37,53,79-82,88,100,106,110-111,113,119,135,139,143-144,179,199,254-255,280,311,389,427,443-445,464-465,497,513-515,543-544,548,554,587,593,625,631,636,646,787,808,873,902,990,993,995,1000,1022,1024-1033,1035-1041,1044,1048-1050,1053-1054,1056,1058-1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1761,1801,1900,1935,1998,2000-2003,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000-3001,3128,3268,3306,3389,3689-3690,3703,3986,4000-4001,4045,4899,5000-5001,5003,5009,5050-5051,5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900-5901,6000-6002,6004,6112,6646,6666,7000,7070,7937-7938,8000,8002,8008-8010,8031,8080-8081,8443,8888,9000-9001,9090,9100,9102,9999-10001,10010,32768,32771,49152-49157 -PU53,67-69,111,123,135,137-139,161-162,445,500,514,520,631,996-999,1434,1701,1900,3283,4500,5353,49152-49154 -oA scans/PingSweep --excludefile exclude.ip --min-hostgroup 256 --min-rate=2000 --open')
    #    os.system('cat scans/PingSweep.gnmap | awk \'/Up/{print $2}\' >> alive.ip')
        os.system('grep "Up" scans/PingSweep.gnmap | cut -d " " -f2 |sort -u > alive.ip')
    
    def portScan(self):
        print("#"*92)
        print("\t\tPORT SCAN of target addresses\t\t")
        print("#"*92)
        os.system('nmap -iL alive.ip -sTU -T4 -A -Pn -n -oA scans/portscan -v -p T:3,7,9,13,17,19,21-23,25-26,37,53,79-82,88,100,106,110-111,113,119,135,139,143-144,179,199,254-255,280,311,389,427,443-445,464-465,497,513-515,543-544,548,554,587,593,625,631,636,646,787,808,873,902,990,993,995,1000,1022,1024-1033,1035-1041,1044,1048-1050,1053-1054,1056,1058-1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1761,1801,1900,1935,1998,2000-2003,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000-3001,3128,3268,3306,3389,3689-3690,3703,3986,4000-4001,4045,4899,5000,5003,5009,5050-5051,5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900-5901,6000-6002,6004,6112,6646,6666,7000,7070,7937-7938,8000,8002,8008-8010,8031,8080-8081,8443,8888,9000-9001,9090,9100,9102,9999-10001,10010,32768,32771,49152-49157,U:53,69,123,161,500,1434 --min-hostgroup 256 --min-rate=2000')
    
    def portScanAllPorts(self):
        print("#"*92)
        print("\t\tPORT SCAN of target addresses with all TCP and UDP ports\t\t")
        print("#"*92)
        os.system('nmap -iL alive.ip -sTU -T4 -A -Pn -n -oA scans/portscanAll -v -p T:0-65535,U:0-65535 --min-hostgroup 256 --min-rate=2000')
    
    def portScanAllTcpPorts(self):
        print("#"*92)
        print("\t\tPORT SCAN of target addresses with all TCP ports\t\t")
        print("#"*92)
        os.system('nmap -iL alive.ip -sTU -T4 -A -Pn -n -oA scans/portscanAllTcp -v -p T:0-65535,U:53,69,123,161,500,1434 --min-hostgroup 256 --min-rate=2000')

class parser():
    # simply parses the pingsweep.gnmap file and places any open ports into a text file with the respective IP address in it.
    def nmapScrape(self):
        print("#"*92)
        print("\tCheck files 'IP.txt' in the open-ports folder\t")
        print("#"*92)
        os.system('./nmapscrape.py scans/portscan.gnmap')
    
        # simply parses the pingsweep.gnmap file and places any open ports into a text file with the respective IP address in it.
    def nmapScrapeAllPorts(self):
        print("#"*92)
        print("\tCheck files 'IP.txt' in the open-ports folder\t")
        print("#"*92)
        os.system('./nmapscrape.py scans/portscanAll.gnmap')
    
        # simply parses the pingsweep.gnmap file and places any open ports into a text file with the respective IP address in it.
    def nmapScrapeAllTcpPorts(self):
        print("#"*92)
        print("\tCheck files 'IP.txt' in the open-ports folder\t")
        print("#"*92)
        os.system('./nmapscrape.py scans/portscanAllTcp.gnmap')
    
    # calls nmap_parser.py and writes output to the directory enumeration with filename nmapreport.txt
    def nmapParser(self):
        print("#"*92)
        print("\t\tCheck the file 'nmapreport' in the enumeration folder\t\t")
        print("#"*92)
        os.system('./nmap_parser.py scans/portscan.gnmap > enumeration/nmapreport.txt')
    
    # calls nmap_parser.py and writes output to the directory enumeration with filename nmapreport.txt
    def nmapParserAllPorts(self):
        print("#"*92)
        print("\t\tCheck the file 'nmapreport' in the enumeration folder\t\t")
        print("#"*92)
        os.system('./nmap_parser.py scans/portscanAll.gnmap > enumeration/nmapreport.txt')
    
    # calls nmap_parser.py and writes output to the directory enumeration with filename nmapreport.txt
    def nmapParserAllTcpPorts(self):
        print("#"*92)
        print("\t\tCheck the file 'nmapreport' in the enumeration folder\t\t")
        print("#"*92)
        os.system('./nmap_parser.py scans/portscanAllTcp.gnmap > enumeration/nmapreport.txt')

class nsescans():
    def snmpEnum(self):
        if os.path.exists('open-ports/161.txt'):
            print("#"*61)
            print("\tRunning NSE script against snmp\t")
            print("\tCheck the the snmp file in the nse_scans directory\t")
            print("#"*61)
            SNMP='nmap -sC -sU -p 161 -iL open-ports/161.txt --script=snmp-interfaces,snmp-sysdescr,snmp-netstat,snmp-processes,snmp-brute --script-args snmp-brute.communitiesdb=snmp-default.txt -oN nse_scans/snmp --stats-every 60s --min-hostgroup 256 --min-rate=2000'
            os.system(SNMP)

    def ftpEnum(self):
        if os.path.exists('open-ports/21.txt'):
            print("#"*61)
            print("\tRunning NSE script against ftp\t")
            print("\tCheck the the ftp file in the nse_scans directory\t")
            print("#"*61)
            FTP='nmap -sC -sV -p 21 -iL open-ports/21.txt --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN nse_scans/ftp --stats-every 60s --min-hostgroup 256 --min-rate=2000'
            os.system(FTP)
    
    def httpEnum(self):
        if os.path.exists('open-ports/80.txt'):
            print("#"*61)
            print("\tRunning NSE script against HTTP\t")
            print("\tCheck the the http file in the nse_scans directory\t")
            print("#"*61)
            HTTP='nmap -sC -sV -p 80 -iL open-ports/80.txt --script=http-enum,http-title,http-methods,http-robots.txt,http-trace -d -oN nse_scans/http --stats-every 60s --min-hostgroup 256 --min-rate=2000'
            os.system(HTTP)
    
    def httpaltEnum(self):
        if os.path.exists('open-ports/8080.txt'):
            print("#"*61)
            print("\tRunning NSE script against HTTP-alt 8080\t")
            print("\tCheck the the http-alt file in the nse_scans directory\t")
            print("#"*61)
            HTTPalt='nmap -sC -sV -p 8080 -iL open-ports/8080.txt --script=http-title,http-robots.txt,http-methods -oN nse_scans/http8080 --stats-every 60s --min-hostgroup 256 --min-rate=2000'
            os.system(HTTPalt)
    
    def httpsEnum(self):
        if os.path.exists('open-ports/443.txt'):
            print("#"*61)
            print("\tRunning NSE script against HTTP\t")
            print("\tCheck the the http file in the nse_scans directory\t")
            print("#"*61)
            HTTPS='nmap -sC -sV -p 443 -iL open-ports/443.txt --script=http-title,http-methods,http-robots.txt,http-trace -d -oN nse_scans/https --stats-every 60s --min-hostgroup 256 --min-rate=2000'
            os.system(HTTPS)
    
    def httpsaltEnum(self):
        if os.path.exists('open-ports/8443.txt'):
            print("#"*61)
            print("\tRunning NSE script against HTTP-alt 8443\t")
            print("\tCheck the the http-alt file in the nse_scans directory\t")
            print("#"*61)
            HTTPSalt='nmap -sC -sV -p 8443 -iL open-ports/8443.txt --script=http-title,http-robots.txt,http-methods -oN nse_scans/https8443 --stats-every 60s --min-hostgroup 256 --min-rate=2000'
            os.system(HTTPSalt)
    
    def sslEnum(self):
        if os.path.exists('open-ports/443.txt'):
            print("#"*61)
            print("\tRunning NSE script against SSL\t")
            print("\tCheck the the ssl file in the nse_scans directory\t")
            print("#"*61)
            SSL='nmap -sC -sV -p 443 -iL open-ports/443.txt --version-light --script=ssl-poodle,ssl-heartbleed,ssl-enum-ciphers --script-args vulns.showall -oN nse_scans/ssl --stats-every 60s --min-hostgroup 256 --min-rate=2000'
            os.system(SSL)
    
    def dnsEnum(self):
        if os.path.exists('open-ports/53.txt'):
            print("#"*61)
            print("\tRunning NSE script against DNS\t")
            print("\tCheck the the dns file in the nse_scans directory\t")
            print("#"*61)
            DNS='nmap -sU -p 53 -iL open-ports/53.txt --script=dns-recursion,dns-service-discovery,dns-cache-snoop.nse,dns-nsec-enum --script-args dns-nsec-enum.domains=example.com -oN nse_scans/dns --stats-every 60s --min-hostgroup 256 --min-rate=2000'
            os.system(DNS)
    
    def smtpEnum(self):
        if os.path.exists('open-ports/25.txt'):
            print("#"*61)
            print("\tRunning NSE script against SMTP\t")
            print("\tCheck the the smtp file in the nse_scans directory\t")
            print("#"*61)
            SMTP=('nmap -sC -sV -p 25 -iL open-ports/25.txt --script=smtp-brute,smtp-commands,smtp-open-relay,smtp-enum-users.nse --script-args smtp-enum-users.methods={EXPN,VRFY} -oN nse_scans/smtp --stats-every 60s --min-hostgroup 256 --min-rate=2000')
            os.system(SMTP)
    
    def pop3Enum(self):
        if os.path.exists('open-ports/110.txt'):
            print("#"*61)
            print("\tRunning NSE script against POP3\t")
            print("\tCheck the the smtp file in the nse_scans directory\t")
            print("#"*61)
            POP=('nmap -sC -sV -p 110 -iL open-ports/110.txt --script=pop3-capabilities,pop3-brute -oN nse_scans/pop3 --stats-every 60s --min-hostgroup 256 --min-rate=2000')
            os.system(POP)
    
    def telnetEnum(self):
        if os.path.exists('open-ports/23.txt'):
            print("#"*61)
            print("\tRunning NSE script against TELNET\t")
            print("\tCheck the the telnet file in the nse_scans directory\t")
            print("#"*61)
            TELNET='nmap -sC -sV -p 23 -iL open-ports/23.txt --script=telnet-encryption,banner -oN nse_scans/telnet --stats-every 60s --min-hostgroup 256 --min-rate=2000'
            os.system(TELNET)
    
    def sshEnum(self):
        if os.path.exists('open-ports/22.txt'):
            print("#"*61)
            print("\tRunning NSE script against SSH\t")
            print("\tCheck the the ssh file in the nse_scans directory\t")
            print("#"*61)
            SSH='nmap -sC -sV -p 22 -iL open-ports/22.txt --script=ssh2-enum-algos -oN nse_scans/ssh --stats-every 60s --min-hostgroup 256 --min-rate=2000'
            os.system(SSH)
    
    def smbEnum(self):
        if os.path.exists('open-ports/445.txt'):
            print("#"*61)
            print("\tRunning NSE script against SMB\t")
            print("\tCheck the the smb file in the nse_scans directory\t")
            print("#"*61)
            SMB='nmap -sC -sV  -p 445 -iL open-ports/445.txt --script=smb-enum-shares.nse,smb-os-discovery.nse,smb-enum-users.nse,smb-security-mode -oN nse_scans/smb --stats-every 60s --min-hostgroup 256 --min-rate=2000'
            os.system(SMB)
    
    def mysqlEnum(self):
        if os.path.exists('open-ports/3306.txt'):
            print("#"*61)
            print("\tRunning NSE script against MySQL\t")
            print("\tCheck the the mysql file in the nse_scans directory\t")
            print("#"*61)
            MYSQL="nmap -sC -sV -p 3306 -iL open-ports/3306.txt --script=mysql-empty-password,mysql-brute,mysql-users,mysql-enum,mysql-audit --script-args 'mysql-audit.username='root', \mysql-audit.password='foobar',mysql-audit.filename='nselib/data/mysql-cis.audit' -oN nse_scans/mysql --stats-every 60s --min-hostgroup 256 --min-rate=2000"
            os.system(MYSQL)
    
    def mssqlEnum(self):
        if os.path.exists('open-ports/1433.txt'):
            print("#"*61)
            print("\tRunning NSE script against MsSQL\t")
            print("\tCheck the the mssql file in the nse_scans directory\t")
            print("#"*61)
            MSSQL='nmap -sC -sU -p 1433 -iL open-ports/1433.txt --script=ms-sql-info --script-args mssql.instance-port=1433 --script=broadcast-ms-sql-discover,ms-sql-info --script-args=newtargets -oN nse_scans/mssql --stats-every 60s --min-hostgroup 256 --min-rate=2000'
            os.system(MSSQL)
    
    def mongodbEnum(self):
        if os.path.exists('open-ports/27017.txt'):
            print("#"*61)
            print("\tRunning NSE script against MongoDB\t")
            print("\tCheck the the mssql file in the nse_scans directory\t")
            print("#"*61)
            MONGODB='nmap -sC -sV -p 27017 -iL open-ports/27017.txt --script=mongodb-info,mongodb-databases,mongodb-brute -oN nse_scans/mongodb --stats-every 60s --min-hostgroup 256 --min-rate=2000'
            os.system(MONGODB)
    
    def ntpEnum(self):
        if os.path.exists('open-ports/123.txt'):
            print("#"*61)
            print("\tRunning NSE script for NTP\t")
            print("\tCheck the the NTP file in the nse_scans directory\t")
            print("#"*61)
            NTP='nmap -sU -p 123 -iL open-ports/123.txt --script=ntp-info,ntp-monlist -oN nse_scans/ntp --stats-every 60s --min-hostgroup 256 --min-rate=2000'
            os.system(NTP)
    
    def nfsEnum(self):
        if os.path.exists('open-ports/111.txt'):
            print("#"*61)
            print("\tRunning NSE script for NFS\t")
            print("\tCheck the the NFS file in the nse_scans directory\t")
            print("#"*61)
            NFS='nmap -sV -p 111 -iL open-ports/111.txt --script=nfs-showmount,nfs-ls -oN nse_scans/nfs111 --stats-every 60s --min-hostgroup 256 --min-rate=2000'
            os.system(NFS) # RUN NFS scripts against VNC
    
    def nfsEnum2(self):
        if os.path.exists('open-ports/2049.txt'):
            print("#"*61)
            print("\tRunning NSE script for NFS\t")
            print("\tCheck the the NFS file in the nse_scans directory\t")
            print("#"*61)
            NFS2='nmap -sV -p 2049 -iL open-ports/2049.txt --script=nfs-showmount,nfs-ls -oN nse_scans/nfs2049 --stats-every 60s --min-hostgroup 256 --min-rate=2000'
            os.system(NFS2)
    
    def vncEnum(self):
        if os.path.exists('open-ports/5900.txt'):
            print("#"*61)
            print("\tRunning NSE script against VNC\t")
            print("\tCheck the the vnc file in the nse_scans directory\t")
            print("#"*61)
            VNC='nmap -sC -sV -p 5900 -iL open-ports/5900.txt --script=vnc-brute,banner -oN nse_scans/vnc --stats-every 60s --min-hostgroup 256 --min-rate=2000'
            os.system(VNC)
    
    def oracleTnsEnum(self):
        if os.path.exists('open-ports/1521.txt'):
            print("#"*61)
            print("\tRunning NSE script against ORACLE TNS\t")
            print("\tCheck the the oracletns file in the nse_scans directory\t")
            print("#"*61)
            ORACLE='nmap --script=oracle-sid-brute -p 1521-1560 -iL open-ports/1521.txt -oN nse_scans/oracle --stats-every 60s --min-hostgroup 256 --min-rate=2000'
            os.system(ORACLE)
    
    #def slowlorisEnum(self):
    #    if os.path.exists('open-ports/80.txt'):
    #        print("#"*61)
    #        print("            Running NSE script for slowloris                ")
    #        print("   Check the the slowloris file in the nse_scans directory  ")
    #        print("#"*61)
    #        SLOWLORIS='nmap --script http-slowloris-check -iL open-ports/80.txt -oN nse_scans/slowloris --stats-every 60s --min-hostgroup 256 --min-rate=2000'
    #        os.system(SLOWLORIS)

class misc():
# for tests that either are not nmap or use nmap + other tools
    def ikeEnum(self):
        if os.path.exists('open-ports/500.txt'):
            print("#"*61)
            print("\tRunning NSE script for IKE\t")
            print("\tCheck the the IKE file in the nse_scans directory\t")
            print("#"*61)
            IKE='nmap -sU -p 500 -iL open-ports/500.txt --script=ike-version -oN nse_scans/ike --stats-every 60s --min-hostgroup 256 --min-rate=2000'
            os.system(IKE)
            os.makedirs('nse_scans/IKE') # Make IKE directory for aggressive mode output
            ### Below: Run aggressive IKE scan and print to directory with the IP address found as filename ###
            with open("open-ports/500.txt","r") as f:
                ip_address = f.readline().rstrip()
                while ip_address != "":
                    os.system("ike-scan -A -M %s --id=GroupVPN > nse_scans/IKE/%s.txt" % (ip_address,ip_address))
                    #print ('ip_address')
                    ip_address = f.readline().rstrip()
            f.close()
    
    def ms15034Enum(self):
        if os.path.exists('open-ports/443.txt'):
            print("#"*61)
            print("\tRunning MS15_034 file test\t")
            print("#"*61)
            os.makedirs('nse_scans/MS15034') # Make directory for output
            ### Below: Run ms15_034 check scan ###
            with open("open-ports/443.txt","r") as f:
                ip_address = f.readline().rstrip()
                while ip_address != "":
                    os.system('curl -v https://%s/ -H "Host: hostname" -H "Range: bytes=0-18446744073709551615" -k > nse_scans/MS15034/%s' % (ip_address,ip_address))
                    #print ('ip_address')
                    ip_address = f.readline().rstrip()
            f.close()
    
    # Check for MS14_066 over 443 but only IP's in 3389 - since we can't validate the ciphers over 3389
    def ms14066Enum(self):
        if os.path.exists('open-ports/3389.txt'):
            print("#"*61)
            print("\tRunning WinShock.sh file test for MS14_066\t")
            print("#"*61)
            os.makedirs('nse_scans/MS14066') # Make IKE directory for aggressive mode output
            ### Below: Run winschock scan ###
            with open("open-ports/3389.txt","r") as f:
                winshock = f.readline().rstrip()
                while winshock != "":
                    os.system("./winshock.sh %s > nse_scans/MS14066/%s.txt" % (winshock,winshock))
                    winshock = f.readline().rstrip()
            f.close()
