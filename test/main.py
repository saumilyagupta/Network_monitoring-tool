from scapy.all import sniff, wrpcap 
import networkutils as NU
import csv
import os
import ipaddress

# Define captured packets list and CSV header
captured_packets = []
csv_header = ["Id","Timestamp", "Source IP", "Destination IP", "Source Port", "Destination Port" , "DataSize(Bytes)"]
# Capture packets
def capture_packets(packet):
    # i=i+1
    print()
    
    # print(packet.show())
    # print()
    # print()
    # print()
    # print()



    # Variable iniclization
    Id = None
    source_ip = None
    destination_ip = None
    source_port = None 
    destination_port = None 
    load = None 
    loadSize = None

    # Packet unPacking
    timestamp = NU.unix_to_standard_time(packet.time)
    try :
        if packet['IP']:
            Id = packet['IP'].id
            source_ip = packet['IP'].src
            destination_ip = packet['IP'].dst
    except Exception as e :
        error = e 

    try:   
        if packet['TCP'] and packet['TCP'].sport ==21 or packet['TCP'].sport ==20 or packet['TCP'].dport ==21 or packet['TCP'].dport ==20 :    
            # source_port = packet['TCP'].sport 
            # destination_port = packet['TCP'].dport 
            print("FTP")
       
    except Exception as e :
        error = e        

    try:   
        if packet['TCP']:    
            # source_port = packet['TCP'].sport 
            # destination_port = packet['TCP'].dport 
            print("TCP")
       
    except Exception as e :
        error = e 

    try:   
        if packet['UDP']:    
            # source_port = packet['TCP'].sport 
            # destination_port = packet['TCP'].dport 
            print("UDP")
       
    except Exception as e :
        error = e 

  

    try:   
        if packet["Raw"] :   
            load = packet["Raw"].load
            loadSize = NU.get_data_size(load)
    except Exception as e :
        error = e     


    # print(Id, timestamp , source_ip , source_port , destination_ip , destination_port , loadSize)  
    # print(destination_ip)  
    # print(packet.summary())
    # print("hello j")
    # print(loadSize)
    
  
    captured_packets.append([Id,timestamp , source_ip, destination_ip, source_port, destination_port ,loadSize])



def tcpSniffer(count:int =0 ,sourceIP =None , destinationIP = None, sourcePort = None , destinationPort = None ):
    """
    filter1 = "src host 172.24.28.161"
    filter2 = "tcp"
    filter3 = "dst host 172.24.28.161"
    filter4 = "dst port 23"
    """
    if sourceIP==None and sourceIP==None and destinationIP==None and destinationPort==None:
        sniff(
                # count=10,
                iface="",
                prn=capture_packets, 
                filter="tcp port 21 or tcp port 20"
              )
       
    else:
        
        filter = ""
        if sourceIP!=None and destinationIP!=None:
            if  NU.isValidIPv4(sourceIP) and NU.isValidIPv4(destinationIP):
                filter += f"src host {sourceIP} and dst host {destinationIP}"
        elif sourceIP==None and destinationIP!=None:
            if NU.isValidIPv4(destinationIP):
                filter+= f"dst host {destinationIP}" 
        elif sourceIP!=None and destinationIP==None:
            if NU.isValidIPv4(sourceIP):
                filter+= f"src host {sourceIP}"

        sniff(iface="eth0",prn=capture_packets, filter=filter)


                 
# Start capturing packets
print("Capturing network traffic...")
print(f"index     Time       SrcIP      scrPort      DstIP       DstPort      dataTranferd")

# Sniff all Reqests   
tcpSniffer()

# sniff by preticular Source IP
# tcpSniffer(sourceIP="172.24.16.1")

# sniff by perticular Destination IP
# tcpSniffer(destinationIP="239.255.255.250")

#sniff by perticular sourceIP and destinationIP
# tcpSniffer(sourceIP="172.24.16.1" , destinationIP="239.255.255.250")        



with open("capture.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(csv_header)
    writer.writerows(captured_packets)
print("Capture finished. Data saved to capture.csv")


"""https://stackoverflow.com/questions/59914585/scapy-packet-filtering-from-an-ip-and-with-destination-port-23"""