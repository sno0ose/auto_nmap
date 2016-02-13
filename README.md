# auto_nmap.py
==========
THIS IS A WORK IN PROGRESS - SO NOT DONE YET!

# Install 
================
    [ # ] $ cd auto_nmap
    [ # ] $ ./auto_nmap

# Usage 
================
./auto_nmap

    - Reads from file targets.txt (if one isn't there it will be created for you.)
    - Creates folders scans/enumeration/open-ports/nse_scans
    - All discovered hosts and the ports, etc... will be stored in these folders to use for later screenshot validation

# Description
========
    -  This script will do a nmap discovery ping sweep, then find all open ports, print out a file in enumeration folder.
    -  Next it will print out seperate files per port in the open-ports folder. Finally it will call the
    -  NSE scripting engine and enumerate ftp, smtp, http(s), 8080, dns, smb, snmp, smtp, vnc, ssh, telnet, mysql, mssql, ms14_066, ms15_034, IKE


# Dependencies
========
    These files are included in the .git download.
    -  nmapscrape.py
    -  nmap_parser.py
    -  winshock.sh
    -  exclude.ip
    
# NOTES
========
This script/idea was based on a forum post at pentestgeek.com and scripts written by our own Alton Johnson (nmapscrape.py and nmap_parser.py)
Pentestgeek Forum Post = https://www.pentestgeek.com/ptgforums/viewtopic.php?id=7
