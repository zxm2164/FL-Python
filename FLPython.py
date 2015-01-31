#Author: Zachary Mink
#Date:   December 7th 2014

import subprocess
import sys
import socket
from time import sleep




#Function which pings the IP Address and parses the bash output
#def PingScan(IP_Addr, deviceInfo):
#    ping = subprocess.Popen("ping -c 2 -i 0.1 -W 10 %s" % IP_Addr, stdout=subprocess.PIPE, shell=True)
    
    #loop through each line of the output
    #    for line in ping.stdout:
    #    pass    #"nop" pass statement does nothing
    
    #Test the output for a destination unreachable.  If it has been reached,
    #process the output
    #try:
    #    if line.split(',')[1] == " 0 packets received":
    #        pass
            #delete this entry in the arp table
            #subprocess.Popen("arp -d %s" % IP_Addr, stdout=subprocess.PIPE, shell=True)

#except IndexError:
        #at the end of the loop, line is equal to the desired information
        #       PingKeysList = line.split()[1].split('/')
        #PingValuesList = line.split()[3].split('/')
        
        #PingResults = {}
        
        #loop through the number of fields and create dictionary pairs
        #for index, key in enumerate(PingKeysList):
        #   PingResults[key] = float(PingValuesList[index])
        #print "%s average response time = %d ms" % (IP_Addr, PingResults['avg'])

#if deviceInfo == "y":
#      DeviceInfoScan(IP_Addr)


#Perform an nmap port scan of the possible industrial protocol ports
#covers modbus, profinet, ethernet/ip, OPC

#Scan Industrial Protocol ports with TCP and UDP
def DeviceInfoScan(IP_Addr):
    #Define a dictionary for the industrial protocol ports
    ProtocolDict = dict([("20","FTP"),("69","TFTP"),("115","SFTP"),("23","TELNET"),("80","HTTP"),("502","MODBUS"),("802","MODBUS-SECURE"),("34962","PROFINET-RT-UNICAST"),("34963","PROFINET-RT-MULTICAST"),("34964","PROFINET-CONTEXT-MANAGER"),("2222","ETHERNET/IP-I/O"),("44818","ETHERNET/IP-MESSAGING"),("34980","ETHERCAT"),("4840","OPC-UA"),("4843","OPC-UA-OVER-SSL")])
    
    
    PortScan = subprocess.Popen("nmap -sU -sS -p 20,69,115,23,80,502,802,34962,34963,34964,2222,44818,34980,4840,4843 %s" % IP_Addr, stdout=subprocess.PIPE, shell=True)
    
    count = 0

    for line in PortScan.stdout:
        for key in ProtocolDict:
            NewLine = line.split()
            try:
                Port = NewLine[0].split('/')[0]
                if Port == key:
                    NewLine[2] = ProtocolDict[key]
                    line = " ".join(NewLine)
                    count = 0
                    break
                elif Port == "PORT":
                    count = 0
                    break
                elif Port == "MAC":
                    count = 1
                    break
            except IndexError:
                count = 1
                break
        if count == 0:
            print "{:<10} {:^15} {:<20}".format(*line.split())
        else:
            print line.rstrip('\n')

    print "**************************************************************"

#Discover the MAC address of the host using ARP
def MAC_ARP(IP_Addr):
    pass
    #ARP_Scan = subprocess.Popen("arp %s" % IP_Addr, stdout=subprocess.PIPE, shell=True)
    #print "MAC Address: %s" %

#Use nmap for host discovery - NMAP was used because sudo/root can be used once instead of multiple times
def NMAP_HostDiscovery(Network):
    DiscoveryOut = subprocess.Popen("sudo nmap -sP %s" % Network, stdout=subprocess.PIPE, shell=True)

    b = 0

    for i,line in enumerate(DiscoveryOut.stdout):
        b = b + 1
        if b == 3:
            print "--------------------------------------------------------------"
            b = 0
        print line,


# ModbusNMAP = subprocess.Popen(["nmap -p 502 192.168.0.1"], stdout=subprocess.PIPE, shell=True)
#    ModbusNMAPResultsDict = ModbusNMAP.stdout.read().strip().split('\n')
#    (ModbusNMAPResults, NMAPError) = ModbusNMAP.communicate()
#.encode("utf-8")

#MAIN
sys.stdout.flush()
print ""
txtFile = open("FLPythonASCII","r")
for line in txtFile:
    for char in line:
        sys.stdout.flush()
        sleep(0.001)
        print char.encode("utf-8"),
print "\n"
print "Welcome to FL Python - an Automation Network Utility based on NMAP and Python"
sys.stdout.flush()
sleep(1)
print "Please run this with sudo or root priviledges!"
sys.stdout.flush()
sleep(1)
##Eventually add the ability to login as root here through python

scan =  raw_input("Subnet Scan or Single Machine? [s/m]: ")
Protocols = raw_input("Would you like to scan for open Industrial Protocol Ports? [y/n]: ")

if scan == "m":
    IP_Addr = raw_input("Please enter the IP address you would like to scan: ")
    if Protocols == "y":
        DeviceInfoScan(IP_Addr)
    else:
        NMAP_HostDiscovery(IP_Addr)

elif scan == "s":
    print "Scanning IP's within your computer's subnet..."
    #Use the socket library to determine the IP address of the host
    HostIP = socket.gethostbyname(socket.gethostname())

    #Use CIDR notation for NMAP implementation
    TestIP = HostIP.split('.')
    TestIP[3] = str(0)
    TestNetwork = ".".join(TestIP) + "/24"

    if Protocols == "y":
        DeviceInfoScan(TestNetwork)
    else:
        NMAP_HostDiscovery(TestNetwork)
        Protocols = raw_input("Would you like to scan for protocol info. now? [y/n]:")

        if Protocols == "y":
            MachineOrNet = raw_input("For the subnet or single machine? [s/m]:")
            if MachineOrNet == "m":
                IP = raw_input("Enter the IP you would like to scan:")
                DeviceInfoScan(IP)
            elif MachineOrNet == "s":
                DeviceInfoScan(TestNetwork)
        else:
            print "Thanks and come again"







#Manual IP creation for manual ping scan
    #Assuming a 254 device network..
    #IPList = range(1,255)
    #Loop through the range of IP's and call the ping function
    #for digit in IPList:
    #   if digit != int(HostIP.split('.')[3]):
    #       TestIP = HostIP.split('.')
    #       TestIP[3] = str(digit)
    #       PingScan(".".join(TestIP), deviceInfo)
    #print("Scan Complete")





