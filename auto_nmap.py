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
from core import scans
###############################################################################################################
# logic to see if the folders are already there, if they are delete folders and recreate empty directories
#create new working folders for the scans, enumeration, NSE scans, and open ports\
###############################################################################################################

###############################################################################################################
#                                 Start of the NMAP pingsweep and portscanner
###############################################################################################################
#
# ADD USER INPUT IF THEY WANT TO RUN NSE SCANS OR NOT
# FUTURE FEATURE - USER INPUT ASKING IF THEY ARE DOING AN INTERNAL/EXTERNAL scan if you want to run all 65535 TCP with top 200 UDP ports
#
# quick pingsweep of the network to find the alive hosts. write hosts to file called alive.ip
def pingSweep():
    print("#"*92)
    print("\t\tPING SWEEP of target addresses\t\t")
    print("\t\tCheck the file 'alive.ip' for all the alive hosts\t\t")
    print("#"*92)
#    os.system('nmap -iL targets.ip -sP -PE -oA scans/PingSweep --excludefile exclude.ip -n --open')
    os.system('nmap -sn -PE -iL targets.ip -PS3,7,9,13,17,19,21-23,25-26,37,53,79-82,88,100,106,110-111,113,119,135,139,143-144,179,199,254-255,280,311,389,427,443-445,464-465,497,513-515,543-544,548,554,587,593,625,631,636,646,787,808,873,902,990,993,995,1000,1022,1024-1033,1035-1041,1044,1048-1050,1053-1054,1056,1058-1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1761,1801,1900,1935,1998,2000-2003,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000-3001,3128,3268,3306,3389,3689-3690,3703,3986,4000-4001,4045,4899,5000-5001,5003,5009,5050-5051,5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900-5901,6000-6002,6004,6112,6646,6666,7000,7070,7937-7938,8000,8002,8008-8010,8031,8080-8081,8443,8888,9000-9001,9090,9100,9102,9999-10001,10010,32768,32771,49152-49157 -PU53,67-69,111,123,135,137-139,161-162,445,500,514,520,631,996-999,1434,1701,1900,3283,4500,5353,49152-49154 -oA scans/PingSweep --excludefile exclude.ip --min-hostgroup 256 --min-rate=2000 --open')
#    os.system('cat scans/PingSweep.gnmap | awk \'/Up/{print $2}\' >> alive.ip')
    os.system('grep "Up" scans/PingSweep.gnmap | cut -d " " -f2 |sort -u > alive.ip')

def portScan():
    print("#"*92)
    print("\t\tPORT SCAN of target addresses\t\t")
    print("#"*92)
    os.system('nmap -iL alive.ip -sTU -T4 -A -Pn -n -oA scans/portscan -v -p T:3,7,9,13,17,19,21-23,25-26,37,53,79-82,88,100,106,110-111,113,119,135,139,143-144,179,199,254-255,280,311,389,427,443-445,464-465,497,513-515,543-544,548,554,587,593,625,631,636,646,787,808,873,902,990,993,995,1000,1022,1024-1033,1035-1041,1044,1048-1050,1053-1054,1056,1058-1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1761,1801,1900,1935,1998,2000-2003,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000-3001,3128,3268,3306,3389,3689-3690,3703,3986,4000-4001,4045,4899,5000,5003,5009,5050-5051,5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900-5901,6000-6002,6004,6112,6646,6666,7000,7070,7937-7938,8000,8002,8008-8010,8031,8080-8081,8443,8888,9000-9001,9090,9100,9102,9999-10001,10010,32768,32771,49152-49157,U:53,69,123,161,500,1434 --min-hostgroup 256 --min-rate=2000')

def portScanAllPorts():
    print("#"*92)
    print("\t\tPORT SCAN of target addresses with all TCP and UDP ports\t\t")
    print("#"*92)
    os.system('nmap -iL alive.ip -sTU -T4 -A -Pn -n -oA scans/portscanAll -v -p T:0-65535,U:0-65535 --min-hostgroup 256 --min-rate=2000')

def portScanAllTcpPorts():
    print("#"*92)
    print("\t\tPORT SCAN of target addresses with all TCP ports\t\t")
    print("#"*92)
    os.system('nmap -iL alive.ip -sTU -T4 -A -Pn -n -oA scans/portscanAllTcp -v -p T:0-65535,U:53,69,123,161,500,1434 --min-hostgroup 256 --min-rate=2000')

# simply parses the pingsweep.gnmap file and places any open ports into a text file with the respective IP address in it.
def nmapScrape():
    print("#"*92)
    print("\tCheck files 'IP.txt' in the open-ports folder\t")
    print("#"*92)
    os.system('./nmapscrape.py scans/portscan.gnmap')

    # simply parses the pingsweep.gnmap file and places any open ports into a text file with the respective IP address in it.
def nmapScrapeAllPorts():
    print("#"*92)
    print("\tCheck files 'IP.txt' in the open-ports folder\t")
    print("#"*92)
    os.system('./nmapscrape.py scans/portscanAll.gnmap')

    # simply parses the pingsweep.gnmap file and places any open ports into a text file with the respective IP address in it.
def nmapScrapeAllTcpPorts():
    print("#"*92)
    print("\tCheck files 'IP.txt' in the open-ports folder\t")
    print("#"*92)
    os.system('./nmapscrape.py scans/portscanAllTcp.gnmap')

# calls nmap_parser.py and writes output to the directory enumeration with filename nmapreport.txt
def nmapParser():
    print("#"*92)
    print("\t\tCheck the file 'nmapreport' in the enumeration folder\t\t")
    print("#"*92)
    os.system('./nmap_parser.py scans/portscan.gnmap > enumeration/nmapreport.txt')

# calls nmap_parser.py and writes output to the directory enumeration with filename nmapreport.txt
def nmapParserAllPorts():
    print("#"*92)
    print("\t\tCheck the file 'nmapreport' in the enumeration folder\t\t")
    print("#"*92)
    os.system('./nmap_parser.py scans/portscanAll.gnmap > enumeration/nmapreport.txt')

# calls nmap_parser.py and writes output to the directory enumeration with filename nmapreport.txt
def nmapParserAllTcpPorts():
    print("#"*92)
    print("\t\tCheck the file 'nmapreport' in the enumeration folder\t\t")
    print("#"*92)
    os.system('./nmap_parser.py scans/portscanAllTcp.gnmap > enumeration/nmapreport.txt')


def ikeEnum():
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
                os.system("ike-scan -A -M %s -id GroupVPN > nse_scans/IKE/%s.txt" % (ip_address,ip_address))
                #print ('ip_address')
                ip_address = f.readline().rstrip()
        f.close()

def ms15034Enum():
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
def ms14066Enum():
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

def setup():
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
        print("\tThe file targets.ip has been created targets.ip file in auto_nmap directory - please add target ranges to this file\t")
        print("#"*125)
        print("#"*125)
        exit()

# main
def main():
    nsescans = scans.nsescans()
############################################################ FUTURE FUNCTIONALITY TO BE ADDED ######################################################################################
    if os.geteuid() != 0:
        print("\t[!] you need root privileges to run this script.\n")
        exit()
        
    print("#"*151)
    print("#"*151)
    print("#"*151)
    print("\tWHAT TYPE OF SCAN DO YOU WANT TO RUN????\t")
    print("\t\tSelect 1 for PING Sweep discovery scan\t\t")
    print("\t\tSelect 2 for PING Sweep + Port Scan\t\t")
    print("\t\tSelect 3 for PING Sweep + Port Scan + NSE and other Enumeration\t\t")
    print("\t\tSelect 4 for PING Sweep + Port Scan of all TCP ports\t\t")
    print("\t\tSelect 5 for PING Sweep + Port Scan of all TCP ports + NSE and other Enumeration\t\t")
    print("\t\tSelect 6 for PING Sweep + Port Scan of all TCP and UDP ports (Warning: will take days)\t\t")
    print("\t\tSelect 7 for PING Sweep + Port Scan of all TCP and UDP ports + NSE and other Enumeration  (Warning: will take days)\t\t")
    print("#"*151)
    print("#"*151)
    print("#"*151)
    SCANTYPE = raw_input("You selected TCP Scan Type:").strip()

############################################################ FUTURE FUNCTIONALITY TO BE ADDED ######################################################################################
    try:
        int(SCANTYPE)
        pass
    except ValueError:
        print("\t[!]interger values only !\n")
        main()

    if (int(SCANTYPE)==int(1)):
        try:
            pingSweep()
        except Exception as error:
            print('The Ping Sweep failed to execute', error)
            exit()

    elif (int(SCANTYPE)==int(2)):
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

    elif (int(SCANTYPE)==int(3)):
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
            nsescans.snmpEnum()
        except Exception as error:
            print('The SNMP NSE Script failed', error)
            exit()

        try:
            nsescans.ftpEnum()
        except Exception as error:
            print('The FTP NSE Script failed to execute', error)
            exit()

        try:
            nsescans.httpEnum()
        except Exception as error:
            print('The HTTP NSE Script failed to execute', error)
            exit()

        try:
            nsescans.httpaltEnum()
        except Exception as error:
            print('The HTTP-ALT NSE Script failed to execute', error)
            exit()

        try:
            nsescans.httpsEnum()
        except Exception as error:
            print('The HTTPS NSE Script failed to execute', error)

        try:
            nsescans.httpsaltEnum()
        except Exception as error:
            print('The HTTPs-ALT NSE Script failed to execute', error)
            exit()

	try:
            nsescans.sslEnum()
        except Exception as error:
            print('The SSL NSE Script failed to execute', error)
            exit()

        try:
            nsescans.dnsEnum()
        except Exception as error:
            print('The DNS NSE Script failed to execute', error)
            exit()

        try:
            nsescans.smtpEnum()
        except Exception as error:
            print('The SMTP NSE Script failed to execute', error)
            exit()

        try:
            nsescans.pop3Enum()
        except Exception as error:
            print('The POP3 NSE Script failed to execute', error)
            exit()

        try:
            nsescans.telnetEnum()
        except Exception as error:
            print('The TELNET NSE Script failed to execute', error)
            exit()

        try:
            nsescans.sshEnum()
        except Exception as error:
            print('The SSH NSE Script failed to execute', error)
            exit()

        try:
            nsescans.smbEnum()
        except Exception as error:
            print('The SMB NSE Script failed to execute', error)
            exit()

        try:
            nsescans.mysqlEnum()
        except Exception as error:
            print('The MYSQL NSE Script failed to execute', error)

        try:
            nsescans.mssqlEnum()
        except Exception as error:
            print('The MSSQL NSE Script failed to execute', error)
            exit()

        try:
	    nsescans.mongodbEnum()
	except Exception as error:
            print('The Mongodb NSE Script failed to execute', error)
            exit()
	try:
            nsescans.vncEnum()
        except Exception as error:
            print('The VNC NSE Script failed to execute', error)
            exit()

        try:
            nsescans.oracleTnsEnum()
        except Exception as error:
            print('The Oracle TNS NSE Script failed to execute', error)
            exit()

        try:
            ikeEnum()
        except Exception as error:
            print('The IKE NSE Script failed to execute', error)

        try:
            nsescans.ntpEnum()
        except Exception as error:
            print('The NTP NSE Script failed to execute', error)
            exit()

        try:
            nsescans.nfsEnum()
        except Exception as error:
            print('The NFS NSE Script failed to execute', error)
            exit()

	try:
            nsescans.nfsEnum2()
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

    elif (int(SCANTYPE)==int(4)):
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

    elif (int(SCANTYPE)==int(5)):
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
            nsescans.snmpEnum()
        except Exception as error:
            print('The SNMP NSE Script failed', error)
            exit()

        try:
            nsescans.ftpEnum()
        except Exception as error:
            print('The FTP NSE Script failed to execute', error)
            exit()

        try:
            nsescans.httpEnum()
        except Exception as error:
            print('The HTTP NSE Script failed to execute', error)
            exit()

        try:
            nsescans.httpaltEnum()
        except Exception as error:
            print('The HTTP-ALT NSE Script failed to execute', error)
            exit()

        try:
            nsescans.httpsEnum()
        except Exception as error:
            print('The HTTPS NSE Script failed to execute', error)

        try:
            nsescans.httpsaltEnum()
        except Exception as error:
            print('The HTTPs-ALT NSE Script failed to execute', error)
            exit()

        try:
            nsescans.sslEnum()
        except Exception as error:
            print('The SSL NSE Script failed to execute', error)
            exit()

        try:
            nsescans.dnsEnum()
        except Exception as error:
            print('The DNS NSE Script failed to execute', error)
            exit()

        try:
            nsescans.smtpEnum()
        except Exception as error:
            print('The SMTP NSE Script failed to execute', error)
            exit()

        try:
            nsescans.pop3Enum()
        except Exception as error:
            print('The POP3 NSE Script failed to execute', error)
            exit()

        try:
            nsescans.telnetEnum()
        except Exception as error:
            print('The TELNET NSE Script failed to execute', error)
            exit()

        try:
            nsescans.sshEnum()
        except Exception as error:
            print('The SSH NSE Script failed to execute', error)
            exit()

        try:
            nsescans.smbEnum()
        except Exception as error:
            print('The SMB NSE Script failed to execute', error)
            exit()

        try:
            nsescans.mysqlEnum()
        except Exception as error:
            print('The MYSQL NSE Script failed to execute', error)

        try:
            nsescans.mssqlEnum()
        except Exception as error:
            print('The MSSQL NSE Script failed to execute', error)
            exit()

        try:
            nsescans.mongodbEnum()
        except Exception as error:
            print('The Mongodb NSE Script failed to execute', error)
            exit()
        try:
            nsescans.vncEnum()
        except Exception as error:
            print('The VNC NSE Script failed to execute', error)
            exit()

        try:
            nsescans.oracleTnsEnum()
        except Exception as error:
            print('The Oracle TNS NSE Script failed to execute', error)
            exit()

        try:
            ikeEnum()
        except Exception as error:
            print('The IKE NSE Script failed to execute', error)

        try:
            nsescans.ntpEnum()
        except Exception as error:
            print('The NTP NSE Script failed to execute', error)
            exit()

        try:
            nsescans.nfsEnum()
        except Exception as error:
            print('The NFS NSE Script failed to execute', error)
            exit()

        try:
            nsescans.nfsEnum2()
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

    elif (int(SCANTYPE)==int(6)):
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

    elif (int(SCANTYPE)==int(7)):
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
            nsescans.snmpEnum()
        except Exception as error:
            print('The SNMP NSE Script failed', error)
            exit()

        try:
            nsescans.ftpEnum()
        except Exception as error:
            print('The FTP NSE Script failed to execute', error)
            exit()

        try:
            nsescans.httpEnum()
        except Exception as error:
            print('The HTTP NSE Script failed to execute', error)
            exit()

        try:
            nsescans.httpaltEnum()
        except Exception as error:
            print('The HTTP-ALT NSE Script failed to execute', error)
            exit()

        try:
            nsescans.httpsEnum()
        except Exception as error:
            print('The HTTPS NSE Script failed to execute', error)

        try:
            nsescans.httpsaltEnum()
        except Exception as error:
            print('The HTTPs-ALT NSE Script failed to execute', error)
            exit()

        try:
            nsescans.sslEnum()
        except Exception as error:
            print('The SSL NSE Script failed to execute', error)
            exit()

        try:
            nsescans.dnsEnum()
        except Exception as error:
            print('The DNS NSE Script failed to execute', error)
            exit()

        try:
            nsescans.smtpEnum()
        except Exception as error:
            print('The SMTP NSE Script failed to execute', error)
            exit()

        try:
            nsescans.pop3Enum()
        except Exception as error:
            print('The POP3 NSE Script failed to execute', error)
            exit()

        try:
            nsescans.telnetEnum()
        except Exception as error:
            print('The TELNET NSE Script failed to execute', error)
            exit()

        try:
            nsescans.sshEnum()
        except Exception as error:
            print('The SSH NSE Script failed to execute', error)
            exit()

        try:
            nsescans.smbEnum()
        except Exception as error:
            print('The SMB NSE Script failed to execute', error)
            exit()

        try:
            nsescans.mysqlEnum()
        except Exception as error:
            print('The MYSQL NSE Script failed to execute', error)

        try:
            nsescans.mssqlEnum()
        except Exception as error:
            print('The MSSQL NSE Script failed to execute', error)
            exit()

        try:
            nsescans.mongodbEnum()
        except Exception as error:
            print('The Mongodb NSE Script failed to execute', error)
            exit()
        try:
            nsescans.vncEnum()
        except Exception as error:
            print('The VNC NSE Script failed to execute', error)
            exit()

        try:
            nsescans.oracleTnsEnum()
        except Exception as error:
            print('The Oracle TNS NSE Script failed to execute', error)
            exit()

        try:
            ikeEnum()
        except Exception as error:
            print('The IKE NSE Script failed to execute', error)

        try:
            nsescans.ntpEnum()
        except Exception as error:
            print('The NTP NSE Script failed to execute', error)
            exit()

        try:
            nsescans.nfsEnum()
        except Exception as error:
            print('The NFS NSE Script failed to execute', error)
            exit()

        try:
            nsescans.nfsEnum2()
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

    else:
        print("\t[!]looks like you chose an option thats not avaliable yet\n")
        main()
#	try:
#            slowlorisEnum()
#        except Exception as error:
#            print('The Slowloris NSE Script failed to execute', error)
#            exit()

if __name__ == "__main__":
    setup()
    main()
