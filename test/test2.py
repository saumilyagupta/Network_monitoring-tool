from scapy.all import sniff, wrpcap 
import networkutils as NU
import csv


def capture_packets(packet):

    
    print(packet.show())

    # # Variable iniclization
    # Id = None
    # source_ip = None
    # destination_ip = None
    # source_port = None 
    # destination_port = None 
    # load = None 
    # loadSize = None

    # # Packet unPacking
    # timestamp = NU.unix_to_standard_time(packet.time)
    # try :
    #     if packet['IP']:
    #         Id = packet['IP'].id
    #         source_ip = packet['IP'].src
    #         destination_ip = packet['IP'].dst
    # except Exception as e :
    #     error = e         
    # try:   
    #     if packet['TCP']:    
    #         source_port = packet['TCP'].sport 
    #         destination_port = packet['TCP'].dport         
    # except Exception as e :
    #     error = e 
    # try:   
    #     if packet["Raw"] :   
    #         load = packet["Raw"].load
    #         loadSize = NU.get_data_size(load)
    # except Exception as e :
    #     error = e     


    # print(Id, timestamp , source_ip , source_port , destination_ip , destination_port , loadSize)  
    # print(destination_ip)  
    # print(packet.summary())
    # print("hello j")
    # print(loadSize)


    