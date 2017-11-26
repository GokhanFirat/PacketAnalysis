from scapy.all import *

print "TYPE\t\tSource MAC\t\tDestination MAC\t\tSSID\t\t"
print "-------\t\t-------------\t\t-------------\t\t------------"

class SearchPackets(object):

	def __init__(self):
		self.beaconSrcMacList = [] #to list source mac adress of wireless network  >> for Beacon Packets
		self.beaconDstMacList = [] #to list destination mac adress of wireless network  >> for Beacon Packets
		self.probeReqSrcMacList = [] #to list source mac adress of wireless network  >> for ProbeRequest Packets
		self.probeReqDstMacList = []  #to list source mac adress of wireless network  >> for ProbeRequest Packets
		self.probeRespSrcMacList = []  #to list source mac adress of wireless network  >> for ProbeResponse Packets
		self.probeRespDstMacList = []  #to list source mac adress of wireless network  >> for ProbeResponse Packets
		self.interface = "wlan0mon" #will to use network interface
		self.filter = ""
		self.ssid = ""
		self.addr1 = "" #destination mac adress
		self.addr2 = "" #source mac adress
		self.count = 0 #infinite number of packet catch
		while True:
			sniff(iface = self.interface,count = self.count, prn = self.packetAnalysis)

	

	def packetAnalysis(self,packet):
		
		if packet.haslayer(Dot11Beacon):
			self.ssid = packet.info
			self.beaconSrcMac = packet.addr2;
			self.beaconDstMac = packet.addr1;
			if 	self.beaconSrcMac not in self.beaconSrcMacList:
				#if ssid is not null, if mac adresses not in macLists, append mac adress
				self.beaconDstMacList.append(self.beaconDstMac)
				self.beaconSrcMacList.append(self.beaconSrcMac)
			
				print "Beacon" +"\t\t"+ self.beaconSrcMac + "\t" + self.beaconDstMac + "\t" + self.ssid

		elif packet.haslayer(Dot11ProbeReq):
			self.ssid = packet[Dot11Elt:1].info
			self.probeReqSrcMac = packet.addr2;
			self.probeReqDstMac = packet.addr1;
			if 	self.probeReqSrcMac not in self.probeReqSrcMacList:
				#if ssid is not null, if mac adresses not in macLists, append mac adress
				self.probeReqDstMacList.append(self.probeReqDstMac)
				self.probeReqSrcMacList.append(self.probeReqSrcMac)
			
				print "Probe Request" + "\t" + self.probeReqSrcMac + "\t" + self.probeReqDstMac + "\t" + self.ssid

		elif packet.haslayer(Dot11ProbeResp):
			self.ssid = packet[Dot11Elt:1].info
			self.probeRespSrcMac = packet.addr2;
			self.probeRespDstMac = packet.addr1;
			if 	self.probeRespSrcMac not in self.probeRespSrcMacList:
				#if ssid is not null, if mac adresses not in macLists, append mac adress
				self.probeRespDstMacList.append(self.probeRespDstMac)
				self.probeRespSrcMacList.append(self.probeRespSrcMac)
			
				print "Probe Response" + "\t" + self.probeRespSrcMac + "\t" + self.probeRespDstMac + "\t" + self.ssid

		

if __name__ == "__main__":
	s = SearchPackets()
	