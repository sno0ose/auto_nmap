#!/usr/bin/env python
###############################################################################################################
## [Title]: auto_nmap - automated nmap scanner and calls nse script scans - written in python3
## [Notes]: this file was based on a post at pentestgeek and some scripts by Alton Johnson
## [Author]: brad ammerman
## [Contributor]: jthorpe6
##-------------------------------------------------------------------------------------------------------------
## [Details]:
## This script will do a nmap discovery ping sweep, then find all open ports, print out a file in enumeration
## folder. Next it will print out seperate files per port in the open-ports folder. Finally it will call the
## NSE scripting engine and enumerate ftp, smtp, http, dns, smb, snmp, vnc, ssh, telnet, mysql, mssql...
##-------------------------------------------------------------------------------------------------------------
###############################################################################################################
import shutil,os
from core import scans

# ADD USER INPUT IF THEY WANT TO RUN NSE SCANS OR NOT
# FUTURE FEATURE - USER INPUT ASKING IF THEY ARE DOING AN INTERNAL/EXTERNAL scan if you want to run all 65535 TCP with top 200 UDP ports

def setup():
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
        print("\tThe file targets.ip has been created targets.ip file in auto_nmap directory - please add target ranges to this file\t")
        print("#"*125)
        print("#"*125)
        exit()

# main
def main():
    portscans = scans.portscans()
    parser = scans.parser()
    nsescans = scans.nsescans()
    extra = scans.misc()
############################################################ FUTURE FUNCTIONALITY TO BE ADDED ################################################################
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
    #print("\t\tSelect 6 for PING Sweep + Port Scan of all TCP and UDP ports (Warning: will take days)\t\t")
    #print("\t\tSelect 7 for PING Sweep + Port Scan of all TCP and UDP ports + NSE and other Enumeration  (Warning: will take days)\t\t")
    print("#"*151)
    print("#"*151)
    print("#"*151)
    SCANTYPE = raw_input("You selected TCP Scan Type:").strip()

############################################################ FUTURE FUNCTIONALITY TO BE ADDED ###################################################################
    try:
        int(SCANTYPE)
        pass
    except ValueError:
        print("\t[!]interger values only !\n")
        main()

    if (int(SCANTYPE)==int(1)):
        try:
            portscans.pingSweep()
        except Exception as error:
            print('The Ping Sweep failed to execute', error)
            exit()

    elif (int(SCANTYPE)==int(2)):
        try:
            portscans.pingSweep()
        except Exception as error:
            print('The Ping Sweep failed to execute', error)
            exit()

        try:
            portscans.portScan()
        except Exception as error:
            print('The Port Scan failed to execute', error)
            exit()

	try:
            parser.nmapScrape()
        except Exception as error:
            print('The NmapScrap failed to execute', error)
            exit()
        try:
            parser.nmapParser()
        except Exception as error:
            print('The NMAP Parser failed to execute', error)
            exit()

    elif (int(SCANTYPE)==int(3)):
        try:
            portscans.pingSweep()
        except Exception as error:
            print('The Ping Sweep failed to execute', error)
            exit()

        try:
            portscans.portScan()
        except Exception as error:
            print('The Port Scan failed to execute', error)
            exit()

        try:
            parser.nmapScrape()
        except Exception as error:
            print('The NmapScrap failed to execute', error)
            exit()
        try:
            parser.nmapParser()
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
            extra.ikeEnum()
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
            extra.ms15034Enum()
        except Exception as error:
            print('The curl command failed to execute', error)
            exit()

        try:
            extra.ms14066Enum()
        except Exception as error:
            print('The curl command failed to execute', error)
            exit()

#	try:
#            nsescans.slowlorisEnum()
#        except Exception as error:
#            print('The Slowloris NSE Script failed to execute', error)
#            exit()

    elif (int(SCANTYPE)==int(4)):
        try:
            portscans.pingSweep()
        except Exception as error:
            print('The Ping Sweep failed to execute', error)
            exit()

        try:
            portscans.portScanAllTcpPorts()
        except Exception as error:
            print('The Port Scan failed to execute', error)
            exit()

        try:
            parser.nmapScrapeAllTcpPorts()
        except Exception as error:
            print('The NmapScrap failed to execute', error)
            exit()
        try:
            parser.nmapParserAllTcpPorts()
        except Exception as error:
            print('The NMAP Parser failed to execute', error)
            exit()

    elif (int(SCANTYPE)==int(5)):
        try:
            portscans.pingSweep()
        except Exception as error:
            print('The Ping Sweep failed to execute', error)
            exit()

        try:
            portscans.portScanAllTcpPorts()
        except Exception as error:
            print('The Port Scan failed to execute', error)
            exit()

        try:
            parser.nmapScrapeAllTcpPorts()
        except Exception as error:
            print('The NmapScrap failed to execute', error)
            exit()
        try:
            parser.nmapParserAllTcpPorts()
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
            extra.ikeEnum()
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
            extra.ms15034Enum()
        except Exception as error:
            print('The curl command failed to execute', error)
            exit()

        try:
            extra.ms14066Enum()
        except Exception as error:
            print('The curl command failed to execute', error)
            exit()

#	try:
#            nsescans.slowlorisEnum()
#        except Exception as error:
#            print('The Slowloris NSE Script failed to execute', error)
#            exit()

    elif (int(SCANTYPE)==int(6)):
        try:
            portscans.pingSweep()
        except Exception as error:
            print('The Ping Sweep failed to execute', error)
            exit()

        try:
            portscans.portScanAllPorts()
        except Exception as error:
            print('The Port Scan failed to execute', error)
            exit()

        try:
            parser.nmapScrapeAllPorts()
        except Exception as error:
            print('The NmapScrap failed to execute', error)
            exit()
        try:
            parser.nmapParserAllPorts()
        except Exception as error:
            print('The NMAP Parser failed to execute', error)
            exit()

    elif (int(SCANTYPE)==int(7)):
        try:
            portscans.pingSweep()
        except Exception as error:
            print('The Ping Sweep failed to execute', error)
            exit()

        try:
            portscans.portScanAllPorts()
        except Exception as error:
            print('The Port Scan failed to execute', error)
            exit()

        try:
            parser.nmapScrapeAllPorts()
        except Exception as error:
            print('The NmapScrap failed to execute', error)
            exit()
        try:
            parser.nmapParserAllPorts()
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
            extra.ikeEnum()
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
            extra.ms15034Enum()
        except Exception as error:
            print('The curl command failed to execute', error)
            exit()

        try:
            extra.ms14066Enum()
        except Exception as error:
            print('The curl command failed to execute', error)
            exit()

#	try:
#            nsescans.slowlorisEnum()
#        except Exception as error:
#            print('The Slowloris NSE Script failed to execute', error)
#            exit()

    else:
        print("\t[!]looks like you chose an option thats not avaliable yet\n")
        main()

if __name__ == "__main__":
    setup()
    main()
