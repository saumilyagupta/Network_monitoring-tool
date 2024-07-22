from django.http import HttpResponse,JsonResponse
from django.utils import timezone 
from network.models import NetworkData
from scapy.all import sniff
from network.networkutils import *
from datetime import datetime
import threading
import time

class TCPSniffer:
    def __init__(self):
        self.is_running = False
        self.sniffer_thread = None

    def is_sniffer_running(self):
        return self.is_running

    def capture_packets(self, packet):
        index = None
        source_ip = None
        destination_ip = None
        source_port = None 
        destination_port = None 
        load = None 
        loadSize = None
        packet_type = None
        try :
            if packet['IP']:
                index = packet['IP'].id
                source_ip = packet['IP'].src
                destination_ip = packet['IP'].dst
        except Exception as e :
            error = e         
        try:   
            if packet['TCP']:    
                source_port = packet['TCP'].sport 
                destination_port = packet['TCP'].dport    
                if source_port == 21 or source_port == 20 and destination_port == 21 and destination_port == 20 :
                    packet_type ="FTP"
                else:
                    packet_type = "TCP"    
        except Exception as e :
            error = e 

        try:   
            if packet['UDP']:    
                source_port = packet['UDP'].sport 
                destination_port = packet['UDP'].dport    
                packet_type = "UDP"    
        except Exception as e :
            error = e 

        try:   
            if packet["Raw"] :   
                load = packet["Raw"].load
                loadSize = get_data_size(load)/1024
        except Exception as e :
            error = e
        
        new_data = NetworkData.objects.create(
                                            TimeStamp = timezone.now(),
                                            Index =  index,
                                            SourceIP = source_ip,
                                            SourcePORT = source_port,
                                            DestinationIP = destination_ip,
                                            DestinationPORT = destination_port,
                                            DataLoad = loadSize,
                                            PackageType =packet_type
                                            )
        new_data.save()

        # print(packet.summary())

    def start(self, count=0, sourceIP=None, destinationIP=None, sourcePort=None, destinationPort=None,protocal='All'):
        if self.is_running:
            print("Sniffer is already running.")
            return 

        filter = ""
        if sourceIP and destinationIP:
            if self.isValidIPv4(sourceIP) and self.isValidIPv4(destinationIP):
                filter += f"src host {sourceIP} and dst host {destinationIP}"
        elif destinationIP:
            if self.isValidIPv4(destinationIP):
                filter += f"dst host {destinationIP}"
        elif sourceIP:
            if self.isValidIPv4(sourceIP):
                filter += f"src host {sourceIP}"
        
        if sourcePort:
            filter += f" and src port {sourcePort}"
        if destinationPort:
            filter += f" and dst port {destinationPort}"


        if sourceIP==None and destinationIP==None:
            if protocal == "All":
                filter = filter
            if protocal == "TCP":
                filter += "tcp"
            if protocal == "UDP":
                filter += "udp"
            if protocal == "FTP":
                filter += "tcp port 21 or tcp port 20"        

            
        self.is_running = True
        self.sniffer_thread = threading.Thread(target=self._sniff, args=(count, filter))
        self.sniffer_thread.start()
        print("Sniffer started.")
        

    def _sniff(self, count, filter):
        sniff(iface="", prn=self.capture_packets, filter=filter, count=count, stop_filter=lambda x: not self.is_running)

    def stop(self):
        if not self.is_running:
            print("Sniffer is not running.")
            
        
        self.is_running = False
        if self.sniffer_thread:
            self.sniffer_thread.join()
        print("Sniffer stopped.")


    @staticmethod
    def isValidIPv4(ip):
        try:
            ipaddress.IPv4Address(ip)
            return True
        except Exception as e :
                return False    

        

# Usage:

if __name__ == "__main__":
    sniffer = TCPSniffer()
    sniffer.start()
    time.sleep(120)
    sniffer.stop()