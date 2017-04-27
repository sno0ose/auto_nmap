#!/usr/bin/env python

import os

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
    
    #def slowlorisEnum():
    #    if os.path.exists('open-ports/80.txt'):
    #        print("#"*61)
    #        print("            Running NSE script for slowloris                ")
    #        print("   Check the the slowloris file in the nse_scans directory  ")
    #        print("#"*61)
    #        SLOWLORIS='nmap --script http-slowloris-check -iL open-ports/80.txt -oN nse_scans/slowloris --stats-every 60s --min-hostgroup 256 --min-rate=2000'
    #        os.system(SLOWLORIS)
