#!/usr/bin/python
###############################################################################################################
## [Title]: auto_nmap - automated nmap scanner and calls nse script scans - written in python3
## [Notes]: this file was based on a post at pentestgeek and some scripts by Alton Johnson
## [Author]: brad ammerman
##-------------------------------------------------------------------------------------------------------------
## [Details]:
## This script will do a nmap discovery ping sweep, then find all open ports, print out a file in enumeration
## folder. Next it will print out seperate files per port in the open-ports folder. Finally it will call the
## NSE scripting engine and enumerate ftp, smtp, http, dns, smb, snmp, vnc, ssh, telnet, mysql, mssql...
##-------------------------------------------------------------------------------------------------------------
###############################################################################################################
import shutil,os
###############################################################################################################
# logic to see if the folders are already there, if they are delete folders and recreate empty directories
#create new working folders for the scans, enumeration, NSE scans, and open ports\
###############################################################################################################
# can add a select yes to delete folders
if os.path.exists('open-ports'):
    shutil.rmtree('open-ports') # Remove open-ports directory

os.makedirs('open-ports') # Make open-ports directory

if os.path.exists('scans'):
    shutil.rmtree('scans') # Remove scans directory

os.makedirs('scans') # Make scans directory

if os.path.exists('enumeration'):
    shutil.rmtree('enumeration') # Remove enumeration directory

os.makedirs('enumeration') # Make enumeration directory

if os.path.exists('nse_scans'):
    shutil.rmtree('nse_scans') # Remove nse_scans directory

os.makedirs('nse_scans') # Make nse_scans directory

#remove alive.ip if it is there - will be from a previous scan / engagement
if os.path.isfile('alive.ip'):
    os.remove('alive.ip')

# check to see if the targets.ip file in the the auto_nmap directory, if not create it.
if  os.path.exists('targets.ip'):
    print(" targets.ip file has been found")
else:
    print("The File targets.ip is not found")
    open('targets.ip', 'a').close()
    print("#"*125)
    print("#"*125)
    print("    The file targets.ip has been created targets.ip file in auto_nmap directory - please add target ranges to this file     ")
    print("#"*125)
    print("#"*125)
    exit()
###############################################################################################################
###############################################################################################################
#                                 Start of the NMAP pingsweep and portscanner
###############################################################################################################
###############################################################################################################
#
# ADD USER INPUT IF THEY WANT TO RUN NSE SCANS OR NOT
# FUTURE FEATURE - USER INPUT ASKING IF THEY ARE DOING AN INTERNAL/EXTERNAL scan if you want to run all 65535 TCP with top 200 UDP ports
#
# quick pingsweep of the network to find the alive hosts. write hosts to file called alive.ip
def pingSweep():
    print("")
    print("")
    print("#"*92)
    print("                          PING SWEEP of target addresses                                   ")
    print("                     Check the file 'alive.ip' for all the alive hosts                     ")
    print("#"*92)
#    os.system('nmap -iL targets.ip -sP -PE -oA scans/PingSweep --excludefile exclude.ip -n --open')
    os.system('nmap -sn -PE -iL targets.ip -PS3,7,9,13,17,19,21-23,25-26,37,53,79-82,88,100,106,110-111,113,119,135,139,143-144,179,199,254-255,280,311,389,427,443-445,464-465,497,513-515,543-544,548,554,587,593,625,631,636,646,787,808,873,902,990,993,995,1000,1022,1024-1033,1035-1041,1044,1048-1050,1053-1054,1056,1058-1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1761,1801,1900,1935,1998,2000-2003,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000-3001,3128,3268,3306,3389,3689-3690,3703,3986,4000-4001,4045,4899,5000-5001,5003,5009,5050-5051,5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900-5901,6000-6002,6004,6112,6646,6666,7000,7070,7937-7938,8000,8002,8008-8010,8031,8080-8081,8443,8888,9000-9001,9090,9100,9102,9999-10001,10010,32768,32771,49152-49157 -PU53,67-69,111,123,135,137-139,161-162,445,500,514,520,631,996-999,1434,1701,1900,3283,4500,5353,49152-49154 -oA scans/PingSweep --excludefile exclude.ip --min-hostgroup 256 --min-rate=2000 --open')
#    os.system('cat scans/PingSweep.gnmap | awk \'/Up/{print $2}\' >> alive.ip')
    os.system('grep "Up" scans/PingSweep.gnmap | cut -d " " -f2 |sort -u > alive.ip')

def portScan():
    print("")
    print("")
    print("###########################################################################################")
    print("                          PORT SCAN of target addresses                                    ")
    print("#"*92)
    os.system('nmap -iL alive.ip -sTU -T4 -A -Pn -n -oA scans/portscan -v -p T:3,7,9,13,17,19,21-23,25-26,37,53,79-82,88,100,106,110-111,113,119,135,139,143-144,179,199,254-255,280,311,389,427,443-445,464-465,497,513-515,543-544,548,554,587,593,625,631,636,646,787,808,873,902,990,993,995,1000,1022,1024-1033,1035-1041,1044,1048-1050,1053-1054,1056,1058-1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1761,1801,1900,1935,1998,2000-2003,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000-3001,3128,3268,3306,3389,3689-3690,3703,3986,4000-4001,4045,4899,5000,5003,5009,5050-5051,5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900-5901,6000-6002,6004,6112,6646,6666,7000,7070,7937-7938,8000,8002,8008-8010,8031,8080-8081,8443,8888,9000-9001,9090,9100,9102,9999-10001,10010,32768,32771,49152-49157,U:53,69,123,161,500,1434 --min-hostgroup 256 --min-rate=2000')

def portScanAllPorts():
    print("")
    print("")
    print("#"*92)
    print("                          PORT SCAN of target addresses with all TCP and UDP ports                                    ")
    print("#"*92)
    os.system('nmap -iL alive.ip -sTU -T4 -A -Pn -n -oA scans/portscanAll -v -p T:0-65535,U:0-65535 --min-hostgroup 256 --min-rate=2000')

def portScanAllTcpPorts():
    print("")
    print("")
    print("#"*92)
    print("                          PORT SCAN of target addresses with all TCP ports                                    ")
    print("#"*92)
    os.system('nmap -iL alive.ip -sTU -T4 -A -Pn -n -oA scans/portscanAllTcp -v -p T:0-65535,U:53,69,123,161,500,1434 --min-hostgroup 256 --min-rate=2000')

# simply parses the pingsweep.gnmap file and places any open ports into a text file with the respective IP address in it.
def nmapScrape():
    print("")
    print("")
    print("#"*92)
    print("                         Check files 'IP.txt' in the open-ports folder                     ")
    print("#"*92)
    os.system('./nmapscrape.py scans/portscan.gnmap')

    # simply parses the pingsweep.gnmap file and places any open ports into a text file with the respective IP address in it.
def nmapScrapeAllPorts():
    print("")
    print("")
    print("#"*92)
    print("                         Check files 'IP.txt' in the open-ports folder                     ")
    print("#"*92)
    os.system('./nmapscrape.py scans/portscanAll.gnmap')

    # simply parses the pingsweep.gnmap file and places any open ports into a text file with the respective IP address in it.
def nmapScrapeAllTcpPorts():
    print("")
    print("")
    print("#"*92)
    print("                         Check files 'IP.txt' in the open-ports folder                     ")
    print("#"*92)
    os.system('./nmapscrape.py scans/portscanAllTcp.gnmap')

# calls nmap_parser.py and writes output to the directory enumeration with filename nmapreport.txt
def nmapParser():
    print("")
    print("")
    print("#"*92)
    print("                 Check the file 'nmapreport' in the enumeration folder                     ")
    print("#"*92)
    os.system('./nmap_parser.py scans/portscan.gnmap > enumeration/nmapreport.txt')


# calls nmap_parser.py and writes output to the directory enumeration with filename nmapreport.txt
def nmapParserAllPorts():
    print("")
    print("")
    print("#"*92)
    print("                 Check the file 'nmapreport' in the enumeration folder                     ")
    print("#"*92)
    os.system('./nmap_parser.py scans/portscanAll.gnmap > enumeration/nmapreport.txt')

# calls nmap_parser.py and writes output to the directory enumeration with filename nmapreport.txt
def nmapParserAllTcpPorts():
    print("")
    print("")
    print("#"*92)
    print("                 Check the file 'nmapreport' in the enumeration folder                     ")
    print("#"*92)
    os.system('./nmap_parser.py scans/portscanAllTcp.gnmap > enumeration/nmapreport.txt')
###############################################################################################################
###############################################################################################################
#                                 Start of the NSE scripts
#                 for each port found in open-ports use NSE against the file.txt
#                       found and run more involved scripts against the port
###############################################################################################################
###############################################################################################################
def snmpEnum():
    if os.path.exists('open-ports/161.txt'):
        print("#"*61)
        print("                Running NSE script against snmp             ")
        print("     Check the the snmp file in the nse_scans directory     ")
        print("#"*61)
        SNMP='nmap -sC -sU -p 161 -iL open-ports/161.txt --script=snmp-interfaces,snmp-sysdescr,snmp-netstat,snmp-processes,snmp-brute --script-args snmp-brute.communitiesdb=snmp-default.txt -oN nse_scans/snmp --stats-every 60s --min-hostgroup 256 --min-rate=2000'
        os.system(SNMP)

def ftpEnum():
    if os.path.exists('open-ports/21.txt'):
        print("#"*61)
        print("                Running NSE script against ftp              ")
        print("     Check the the ftp file in the nse_scans directory      ")
        print("#"*61)
        FTP='nmap -sC -sV -p 21 -iL open-ports/21.txt --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN nse_scans/ftp --stats-every 60s --min-hostgroup 256 --min-rate=2000'
        os.system(FTP)

def httpEnum():
    if os.path.exists('open-ports/80.txt'):
        print("#"*61)
        print("                Running NSE script against HTTP             ")
        print("     Check the the http file in the nse_scans directory     ")
        print("#"*61)
        HTTP='nmap -sC -sV -p 80 -iL open-ports/80.txt --script=http-enum,http-title,http-methods,http-robots.txt,http-trace -d -oN nse_scans/http --stats-every 60s --min-hostgroup 256 --min-rate=2000'
        os.system(HTTP)

def httpaltEnum():
    if os.path.exists('open-ports/8080.txt'):
        print("#"*61)
        print("          Running NSE script against HTTP-alt 8080          ")
        print("     Check the the http-alt file in the nse_scans directory ")
        print("#"*61)
        HTTPalt='nmap -sC -sV -p 8080 -iL open-ports/8080.txt --script=http-title,http-robots.txt,http-methods -oN nse_scans/http8080 --stats-every 60s --min-hostgroup 256 --min-rate=2000'
        os.system(HTTPalt)

def httpsEnum():
    if os.path.exists('open-ports/443.txt'):
        print("#"*61)
        print("                Running NSE script against HTTP             ")
        print("     Check the the http file in the nse_scans directory     ")
        print("#"*61)
        HTTPS='nmap -sC -sV -p 443 -iL open-ports/443.txt --script=http-title,http-methods,http-robots.txt,http-trace -d -oN nse_scans/https --stats-every 60s --min-hostgroup 256 --min-rate=2000'
        os.system(HTTPS)

def httpsaltEnum():
    if os.path.exists('open-ports/8443.txt'):
        print("#"*61)
        print("          Running NSE script against HTTP-alt 8443          ")
        print("     Check the the http-alt file in the nse_scans directory ")
        print("#"*61)
        HTTPSalt='nmap -sC -sV -p 8443 -iL open-ports/8443.txt --script=http-title,http-robots.txt,http-methods -oN nse_scans/https8443 --stats-every 60s --min-hostgroup 256 --min-rate=2000'
        os.system(HTTPSalt)

def sslEnum():
    if os.path.exists('open-ports/443.txt'):
        print("#"*61)
        print("                Running NSE script against SSL              ")
        print("     Check the the ssl file in the nse_scans directory      ")
        print("#"*61)
        SSL='nmap -sC -sV -p 443 -iL open-ports/443.txt --version-light --script=ssl-poodle,ssl-heartbleed,ssl-enum-ciphers --script-args vulns.showall -oN nse_scans/ssl --stats-every 60s --min-hostgroup 256 --min-rate=2000'
        os.system(SSL)

def dnsEnum():
    if os.path.exists('open-ports/53.txt'):
        print("#"*61)
        print("                Running NSE script against DNS              ")
        print("     Check the the dns file in the nse_scans directory      ")
        print("#"*61)
        DNS='nmap -sU -p 53 -iL open-ports/53.txt --script=dns-recursion,dns-service-discovery,dns-cache-snoop.nse,dns-nsec-enum --script-args dns-nsec-enum.domains=example.com -oN nse_scans/dns --stats-every 60s --min-hostgroup 256 --min-rate=2000'
        os.system(DNS)

def smtpEnum():
    if os.path.exists('open-ports/25.txt'):
        print("#############################################################")
        print("                Running NSE script against SMTP              ")
        print("     Check the the smtp file in the nse_scans directory      ")
        print("#############################################################")
        SMTP=('nmap -sC -sV -p 25 -iL open-ports/25.txt --script=smtp-brute,smtp-commands,smtp-open-relay,smtp-enum-users.nse --script-args smtp-enum-users.methods={EXPN,VRFY} -oN nse_scans/smtp --stats-every 60s --min-hostgroup 256 --min-rate=2000')
        os.system(SMTP)

def pop3Enum():
    if os.path.exists('open-ports/110.txt'):
        print("#############################################################")
        print("                Running NSE script against POP3              ")
        print("     Check the the smtp file in the nse_scans directory      ")
        print("#############################################################")
        POP=('nmap -sC -sV -p 110 -iL open-ports/110.txt --script=pop3-capabilities,pop3-brute -oN nse_scans/pop3 --stats-every 60s --min-hostgroup 256 --min-rate=2000')
        os.system(POP)

def telnetEnum():
    if os.path.exists('open-ports/23.txt'):
        print("###############################################################")
        print("            Running NSE script against TELNET                  ")
        print("     Check the the telnet file in the nse_scans directory      ")
        print("###############################################################")
        TELNET='nmap -sC -sV -p 23 -iL open-ports/23.txt --script=telnet-encryption,banner -oN nse_scans/telnet --stats-every 60s --min-hostgroup 256 --min-rate=2000'
        os.system(TELNET)

def sshEnum():
    if os.path.exists('open-ports/22.txt'):
        print("#"*61)
        print("            Running NSE script against SSH                  ")
        print("     Check the the ssh file in the nse_scans directory      ")
        print("#"*61)
        SSH='nmap -sC -sV -p 22 -iL open-ports/22.txt --script=ssh2-enum-algos -oN nse_scans/ssh --stats-every 60s --min-hostgroup 256 --min-rate=2000'
        os.system(SSH)

def smbEnum():
    if os.path.exists('open-ports/445.txt'):
        print("#"*61)
        print("            Running NSE script against SMB                  ")
        print("     Check the the smb file in the nse_scans directory      ")
        print("#"*61)
        SMB='nmap -sC -sV  -p 445 -iL open-ports/445.txt --script=smb-enum-shares.nse,smb-os-discovery.nse,smb-enum-users.nse,smb-security-mode -oN nse_scans/smb --stats-every 60s --min-hostgroup 256 --min-rate=2000'
        os.system(SMB)

def mysqlEnum():
    if os.path.exists('open-ports/3306.txt'):
        print("##############################################################")
        print("            Running NSE script against MySQL                  ")
        print("     Check the the mysql file in the nse_scans directory      ")
        print("##############################################################")
        MYSQL="nmap -sC -sV -p 3306 -iL open-ports/3306.txt --script=mysql-empty-password,mysql-brute,mysql-users,mysql-enum,mysql-audit --script-args 'mysql-audit.username='root', \mysql-audit.password='foobar',mysql-audit.filename='nselib/data/mysql-cis.audit' -oN nse_scans/mysql --stats-every 60s --min-hostgroup 256 --min-rate=2000"
        os.system(MYSQL)

def mssqlEnum():
    if os.path.exists('open-ports/1433.txt'):
        print("##############################################################")
        print("            Running NSE script against MsSQL                  ")
        print("     Check the the mssql file in the nse_scans directory      ")
        print("##############################################################")
        MSSQL='nmap -sC -sU -p 1433 -iL open-ports/1433.txt --script=ms-sql-info --script-args mssql.instance-port=1433 --script=broadcast-ms-sql-discover,ms-sql-info --script-args=newtargets -oN nse_scans/mssql --stats-every 60s --min-hostgroup 256 --min-rate=2000'
        os.system(MSSQL)

def mongodbEnum():
    if os.path.exists('open-ports/27017.txt'):
        print("##############################################################")
        print("            Running NSE script against MongoDB                ")
        print("     Check the the mssql file in the nse_scans directory      ")
        print("##############################################################")
        MONGODB='nmap -sC -sV -p 27017 -iL open-ports/27017.txt --script=mongodb-info,mongodb-databases,mongodb-brute -oN nse_scans/mongodb --stats-every 60s --min-hostgroup 256 --min-rate=2000'
        os.system(MONGODB)

def ntpEnum():
    if os.path.exists('open-ports/123.txt'):
        print("#"*61)
        print("            Running NSE script for NTP                ")
        print("   Check the the NTP file in the nse_scans directory        ")
        print("#"*61)
        NTP='nmap -sU -p 123 -iL open-ports/123.txt --script=ntp-info,ntp-monlist -oN nse_scans/ntp --stats-every 60s --min-hostgroup 256 --min-rate=2000'
        os.system(NTP)

def nfsEnum():
    if os.path.exists('open-ports/111.txt'):
        print("#"*61)
        print("            Running NSE script for NFS                ")
        print("   Check the the NFS file in the nse_scans directory        ")
        print("#"*61)
        NFS='nmap -sV -p 111 -iL open-ports/111.txt --script=nfs-showmount,nfs-ls -oN nse_scans/nfs111 --stats-every 60s --min-hostgroup 256 --min-rate=2000'
        os.system(NFS) # RUN NFS scripts against VNC

def nfsEnum2():
    if os.path.exists('open-ports/2049.txt'):
        print("#"*61)
        print("            Running NSE script for NFS                ")
        print("   Check the the NFS file in the nse_scans directory        ")
        print("#"*61)
        NFS2='nmap -sV -p 2049 -iL open-ports/2049.txt --script=nfs-showmount,nfs-ls -oN nse_scans/nfs2049 --stats-every 60s --min-hostgroup 256 --min-rate=2000'
        os.system(NFS2)

def vncEnum():
    if os.path.exists('open-ports/5900.txt'):
        print("#"*61)
        print("            Running NSE script against VNC                  ")
        print("     Check the the vnc file in the nse_scans directory      ")
        print("#"*61)
        VNC='nmap -sC -sV -p 5900 -iL open-ports/5900.txt --script=vnc-brute,banner -oN nse_scans/vnc --stats-every 60s --min-hostgroup 256 --min-rate=2000'
        os.system(VNC)

def oracleTnsEnum():
    if os.path.exists('open-ports/1521.txt'):
        print("#"*61)
        print("            Running NSE script against ORACLE TNS           ")
        print("   Check the the oracletns file in the nse_scans directory  ")
        print("#"*61)
        TNS='nmap --script=oracle-sid-brute -p 1521-1560 -iL open-ports/1521.txt -oN nse_scans/oracle --stats-every 60s --min-hostgroup 256 --min-rate=2000'
        os.system(ORACLE)

#def slowlorisEnum():
#    if os.path.exists('open-ports/80.txt'):
#        print("#"*61)
#        print("            Running NSE script for slowloris                ")
#        print("   Check the the slowloris file in the nse_scans directory  ")
#        print("#"*61)
#        SLOWLORIS='nmap --script http-slowloris-check -iL open-ports/80.txt -oN nse_scans/slowloris --stats-every 60s --min-hostgroup 256 --min-rate=2000'
#        os.system(SLOWLORIS)

def ikeEnum():
    if os.path.exists('open-ports/500.txt'):
        print("#"*61)
        print("            Running NSE script for IKE                      ")
        print("   Check the the IKE file in the nse_scans directory        ")
        print("#"*61)
        IKE='nmap -sU -p 500 -iL open-ports/500.txt --script=ike-version -oN nse_scans/ike --stats-every 60s --min-hostgroup 256 --min-rate=2000'
        os.system(IKE)
        os.makedirs('nse_scans/IKE') # Make IKE directory for aggressive mode output
        ### Below: Run aggressive IKE scan and print to directory with the IP address found as filename ###
        with open("open-ports/500.txt","r") as f:
            ip_address = f.readline().rstrip()
            while ip_address != "":
                os.system("ike-scan -A -M %s -id GroupVPN > nse_scans/IKE/%s.txt" % (ip_address,ip_address))
                #print ('ip_address')
                ip_address = f.readline().rstrip()
        f.close()

def ms15034Enum():
    if os.path.exists('open-ports/443.txt'):
        print("#"*61)
        print("       Running MS15_034 file test            ")
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
def ms14066Enum():
    if os.path.exists('open-ports/3389.txt'):
        print("#"*61)
        print("       Running WinShock.sh file test for MS14_066           ")
        print("#"*61)
        os.makedirs('nse_scans/MS14066') # Make IKE directory for aggressive mode output
        ### Below: Run winschock scan ###
        with open("open-ports/3389.txt","r") as f:
            winshock = f.readline().rstrip()
            while winshock != "":
                os.system("./winshock.sh %s > nse_scans/MS14066/%s.txt" % (winshock,winshock))
                winshock = f.readline().rstrip()
        f.close()

# main
def main():
####################################################################################################################################################################################
####################################################################################################################################################################################
####################################################################################################################################################################################
############################################################ FUTURE FUNCTIONALITY TO BE ADDED ######################################################################################

    print("#"*151)
    print("#"*151)
    print("#"*151)
    print('         WHAT TYPE OF SCAN DO YOU WANT TO RUN????                                       ')
    print("                        Select 1 for PING Sweep discovery scan                               ")
    print("                        Select 2 for PING Sweep + Port Scan                                           ")
    print("                        Select 3 for PING Sweep + Port Scan + NSE and other Enumeration        ")
    print("                        Select 4 for PING Sweep + Port Scan of all TCP ports                                           ")
    print("                        Select 5 for PING Sweep + Port Scan of all TCP ports + NSE and other Enumeration                   ")
    print("                        Select 6 for PING Sweep + Port Scan of all TCP and UDP ports (Warning: will take days)                                          ")
    print("                        Select 7 for PING Sweep + Port Scan of all TCP and UDP ports + NSE and other Enumeration  (Warning: will take days)                   ")
    print("#"*151)
    print("#"*151)
    print("#"*151)
    SCANTYPE = input("You selected TCP Scan Type:")

############################################################ FUTURE FUNCTIONALITY TO BE ADDED ######################################################################################

    if (SCANTYPE==1):
        try:
            pingSweep()
        except Exception as error:
            print('The Ping Sweep failed to execute', error)
            exit()

    if (SCANTYPE==2):
        try:
            pingSweep()
        except Exception as error:
            print('The Ping Sweep failed to execute', error)
            exit()

        try:
            portScan()
        except Exception as error:
            print('The Port Scan failed to execute', error)
            exit()

	try:
            nmapScrape()
        except Exception as error:
            print('The NmapScrap failed to execute', error)
            exit()
        try:
            nmapParser()
        except Exception as error:
            print('The NMAP Parser failed to execute', error)
            exit()

    if (SCANTYPE==3):
        try:
            pingSweep()
        except Exception as error:
            print('The Ping Sweep failed to execute', error)
            exit()

        try:
            portScan()
        except Exception as error:
            print('The Port Scan failed to execute', error)
            exit()

        try:
            nmapScrape()
        except Exception as error:
            print('The NmapScrap failed to execute', error)
            exit()
        try:
            nmapParser()
        except Exception as error:
            print('The NMAP Parser failed to execute', error)
            exit()

        try:
            snmpEnum()
        except Exception as error:
            print('The SNMP NSE Script failed', error)
            exit()

        try:
            ftpEnum()
        except Exception as error:
            print('The FTP NSE Script failed to execute', error)
            exit()

        try:
            httpEnum()
        except Exception as error:
            print('The HTTP NSE Script failed to execute', error)
            exit()

        try:
            httpaltEnum()
        except Exception as error:
            print('The HTTP-ALT NSE Script failed to execute', error)
            exit()

        try:
            httpsEnum()
        except Exception as error:
            print('The HTTPS NSE Script failed to execute', error)

        try:
            httpsaltEnum()
        except Exception as error:
            print('The HTTPs-ALT NSE Script failed to execute', error)
            exit()

	try:
            sslEnum()
        except Exception as error:
            print('The SSL NSE Script failed to execute', error)
            exit()

        try:
            dnsEnum()
        except Exception as error:
            print('The DNS NSE Script failed to execute', error)
            exit()

        try:
            smtpEnum()
        except Exception as error:
            print('The SMTP NSE Script failed to execute', error)
            exit()

        try:
            pop3Enum()
        except Exception as error:
            print('The POP3 NSE Script failed to execute', error)
            exit()

        try:
            telnetEnum()
        except Exception as error:
            print('The TELNET NSE Script failed to execute', error)
            exit()

        try:
            sshEnum()
        except Exception as error:
            print('The SSH NSE Script failed to execute', error)
            exit()

        try:
            smbEnum()
        except Exception as error:
            print('The SMB NSE Script failed to execute', error)
            exit()

        try:
            mysqlEnum()
        except Exception as error:
            print('The MYSQL NSE Script failed to execute', error)

        try:
            mssqlEnum()
        except Exception as error:
            print('The MSSQL NSE Script failed to execute', error)
            exit()

        try:
	    mongodbEnum()
	except Exception as error:
            print('The Mongodb NSE Script failed to execute', error)
            exit()
	try:
            vncEnum()
        except Exception as error:
            print('The VNC NSE Script failed to execute', error)
            exit()

        try:
            oracleTnsEnum()
        except Exception as error:
            print('The Oracle TNS NSE Script failed to execute', error)
            exit()


        try:
            ikeEnum()
        except Exception as error:
            print('The IKE NSE Script failed to execute', error)

        try:
            ntpEnum()
        except Exception as error:
            print('The NTP NSE Script failed to execute', error)
            exit()

        try:
            nfsEnum()
        except Exception as error:
            print('The NFS NSE Script failed to execute', error)
            exit()

	try:
            nfsEnum2()
        except Exception as error:
            print('The NFS NSE Script failed to execute', error)
            exit()

        try:
            ms15034Enum()
        except Exception as error:
            print('The curl command failed to execute', error)
            exit()

        try:
            ms14066Enum()
        except Exception as error:
            print('The curl command failed to execute', error)
            exit()

#	try:
#            slowlorisEnum()
#        except Exception as error:
#            print('The Slowloris NSE Script failed to execute', error)
#            exit()


    if (SCANTYPE==4):
        try:
            pingSweep()
        except Exception as error:
            print('The Ping Sweep failed to execute', error)
            exit()

        try:
            portScanAllTcpPorts()
        except Exception as error:
            print('The Port Scan failed to execute', error)
            exit()

        try:
            nmapScrapeAllTcpPorts()
        except Exception as error:
            print('The NmapScrap failed to execute', error)
            exit()
        try:
            nmapParserAllTcpPorts()
        except Exception as error:
            print('The NMAP Parser failed to execute', error)
            exit()

    if (SCANTYPE==5):
        try:
            pingSweep()
        except Exception as error:
            print('The Ping Sweep failed to execute', error)
            exit()

        try:
            portScanAllTcpPorts()
        except Exception as error:
            print('The Port Scan failed to execute', error)
            exit()

        try:
            nmapScrapeAllTcpPorts()
        except Exception as error:
            print('The NmapScrap failed to execute', error)
            exit()
        try:
            nmapParserAllTcpPorts()
        except Exception as error:
            print('The NMAP Parser failed to execute', error)
            exit()

        try:
            snmpEnum()
        except Exception as error:
            print('The SNMP NSE Script failed', error)
            exit()

        try:
            ftpEnum()
        except Exception as error:
            print('The FTP NSE Script failed to execute', error)
        exit()

        try:
            httpEnum()
        except Exception as error:
            print('The HTTP NSE Script failed to execute', error)
            exit()

        try:
            httpaltEnum()
        except Exception as error:
            print('The HTTP-ALT NSE Script failed to execute', error)
            exit()

        try:
            httpsEnum()
        except Exception as error:
            print('The HTTPS NSE Script failed to execute', error)

        try:
            httpsaltEnum()
        except Exception as error:
            print('The HTTPs-ALT NSE Script failed to execute', error)
            exit()

        try:
            sslEnum()
        except Exception as error:
            print('The SSL NSE Script failed to execute', error)
            exit()

        try:
            dnsEnum()
        except Exception as error:
            print('The DNS NSE Script failed to execute', error)
            exit()

        try:
            smtpEnum()
        except Exception as error:
            print('The SMTP NSE Script failed to execute', error)
            exit()

        try:
            pop3Enum()
        except Exception as error:
            print('The POP3 NSE Script failed to execute', error)
            exit()

        try:
            telnetEnum()
        except Exception as error:
            print('The TELNET NSE Script failed to execute', error)
            exit()

        try:
            sshEnum()
        except Exception as error:
            print('The SSH NSE Script failed to execute', error)
            exit()

        try:
            smbEnum()
        except Exception as error:
            print('The SMB NSE Script failed to execute', error)
            exit()

        try:
            mysqlEnum()
        except Exception as error:
            print('The MYSQL NSE Script failed to execute', error)

        try:
            mssqlEnum()
        except Exception as error:
            print('The MSSQL NSE Script failed to execute', error)
            exit()

        try:
            mongodbEnum()
        except Exception as error:
            print('The Mongodb NSE Script failed to execute', error)
            exit()
        try:
            vncEnum()
        except Exception as error:
            print('The VNC NSE Script failed to execute', error)
            exit()

        try:
            oracleTnsEnum()
        except Exception as error:
            print('The Oracle TNS NSE Script failed to execute', error)
            exit()


        try:
            ikeEnum()
        except Exception as error:
            print('The IKE NSE Script failed to execute', error)

        try:
            ntpEnum()
        except Exception as error:
            print('The NTP NSE Script failed to execute', error)
            exit()

        try:
            nfsEnum()
        except Exception as error:
            print('The NFS NSE Script failed to execute', error)
            exit()

        try:
            nfsEnum2()
        except Exception as error:
            print('The NFS NSE Script failed to execute', error)
            exit()

        try:
            ms15034Enum()
        except Exception as error:
            print('The curl command failed to execute', error)
            exit()

        try:
            ms14066Enum()
        except Exception as error:
            print('The curl command failed to execute', error)
            exit()

#	try:
#            slowlorisEnum()
#        except Exception as error:
#            print('The Slowloris NSE Script failed to execute', error)
#            exit()



    if (SCANTYPE==6):
        try:
            pingSweep()
        except Exception as error:
            print('The Ping Sweep failed to execute', error)
            exit()

        try:
            portScanAllPorts()
        except Exception as error:
            print('The Port Scan failed to execute', error)
            exit()

        try:
            nmapScrapeAllPorts()
        except Exception as error:
            print('The NmapScrap failed to execute', error)
            exit()
        try:
            nmapParserAllPorts()
        except Exception as error:
            print('The NMAP Parser failed to execute', error)
            exit()

    if (SCANTYPE==7):
        try:
            pingSweep()
        except Exception as error:
            print('The Ping Sweep failed to execute', error)
            exit()

        try:
            portScanAllPorts()
        except Exception as error:
            print('The Port Scan failed to execute', error)
            exit()

        try:
            nmapScrapeAllPorts()
        except Exception as error:
            print('The NmapScrap failed to execute', error)
            exit()
        try:
            nmapParserAllPorts()
        except Exception as error:
            print('The NMAP Parser failed to execute', error)
            exit()

        try:
            snmpEnum()
        except Exception as error:
            print('The SNMP NSE Script failed', error)
            exit()

        try:
            ftpEnum()
        except Exception as error:
            print('The FTP NSE Script failed to execute', error)
            exit()

        try:
            httpEnum()
        except Exception as error:
            print('The HTTP NSE Script failed to execute', error)
            exit()

        try:
            httpaltEnum()
        except Exception as error:
            print('The HTTP-ALT NSE Script failed to execute', error)
            exit()

        try:
            httpsEnum()
        except Exception as error:
            print('The HTTPS NSE Script failed to execute', error)

        try:
            httpsaltEnum()
        except Exception as error:
            print('The HTTPs-ALT NSE Script failed to execute', error)
            exit()

        try:
            sslEnum()
        except Exception as error:
            print('The SSL NSE Script failed to execute', error)
            exit()

        try:
            dnsEnum()
        except Exception as error:
            print('The DNS NSE Script failed to execute', error)
            exit()

        try:
            smtpEnum()
        except Exception as error:
            print('The SMTP NSE Script failed to execute', error)
            exit()

        try:
            pop3Enum()
        except Exception as error:
            print('The POP3 NSE Script failed to execute', error)
            exit()

        try:
            telnetEnum()
        except Exception as error:
            print('The TELNET NSE Script failed to execute', error)
            exit()

        try:
            sshEnum()
        except Exception as error:
            print('The SSH NSE Script failed to execute', error)
            exit()

        try:
            smbEnum()
        except Exception as error:
            print('The SMB NSE Script failed to execute', error)
            exit()

        try:
            mysqlEnum()
        except Exception as error:
            print('The MYSQL NSE Script failed to execute', error)

        try:
            mssqlEnum()
        except Exception as error:
            print('The MSSQL NSE Script failed to execute', error)
            exit()

        try:
            mongodbEnum()
        except Exception as error:
            print('The Mongodb NSE Script failed to execute', error)
            exit()
        try:
            vncEnum()
        except Exception as error:
            print('The VNC NSE Script failed to execute', error)
            exit()

        try:
            oracleTnsEnum()
        except Exception as error:
            print('The Oracle TNS NSE Script failed to execute', error)
            exit()


        try:
            ikeEnum()
        except Exception as error:
            print('The IKE NSE Script failed to execute', error)

        try:
            ntpEnum()
        except Exception as error:
            print('The NTP NSE Script failed to execute', error)
            exit()

        try:
            nfsEnum()
        except Exception as error:
            print('The NFS NSE Script failed to execute', error)
            exit()

        try:
            nfsEnum2()
        except Exception as error:
            print('The NFS NSE Script failed to execute', error)
            exit()

        try:
            ms15034Enum()
        except Exception as error:
            print('The curl command failed to execute', error)
            exit()

        try:
            ms14066Enum()
        except Exception as error:
            print('The curl command failed to execute', error)
            exit()

#	try:
#            slowlorisEnum()
#        except Exception as error:
#            print('The Slowloris NSE Script failed to execute', error)
#            exit()



if __name__ == "__main__":
    main()
