#include "LivePacketCapture.hpp"
#include <iostream>
#include <cstring>
#include <cerrno>

std::vector<std::string>	LivePacketCapture::Interfaces()
{
  std::vector<std::string>	interfaces;
  struct ifaddrs		*addrs;

  getifaddrs(&addrs);

  struct ifaddrs		*tmp = addrs;
  
  while (tmp) {
    if (tmp-> ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET)
      interfaces.push_back(tmp->ifa_name);
    tmp = tmp->ifa_next;
  }
  freeifaddrs(addrs);
  return interfaces;
}

std::vector<packet_t>		LivePacketCapture::Load(std::string const &filename)
{
  std::ifstream			file;
  pcap_hdr_t			pcaph;

  file.open(filename.c_str(), std::ofstream::in | std::ofstream::binary);
  file.read((char *)&pcaph, sizeof(pcap_hdr_t));
  if (pcaph.magic_number != 0xA1B2C3D4)
    throw std::string("Load: Invalid file");

  std::vector<packet_t>		packets;
  
  pcaprec_hdr_t			pcaprech;

  packet_t			packet;
  ssize_t			header_size;

  struct stat			stat_buf;
  ssize_t			file_size = 0;
  
  if (stat(filename.c_str(), &stat_buf) >= 0)
    file_size = stat_buf.st_size - sizeof(pcap_hdr_t);
  while (file_size > 0) {
    memset(&pcaprech, 0, sizeof(pcaprec_hdr_t));
    memset(&packet, 0, sizeof(packet_t));
    file.read((char *)&pcaprech, sizeof(pcaprec_hdr_t));
    file_size -= sizeof(pcaprec_hdr_t);
    file.read((char *)&(packet.eth), sizeof(struct ethhdr));
    file.read((char *)&(packet.iph), sizeof(struct iphdr));

    header_size = sizeof(struct ethhdr) + sizeof(struct iphdr);
    
    switch (packet.iph.protocol) {
    case ICMP:
      file.read((char *)&(packet.icmph), sizeof(struct icmphdr));
      header_size += sizeof(struct icmphdr);
      break;
    case TCP:
      file.read((char *)&(packet.tcph), sizeof(struct tcphdr));
      header_size += sizeof(struct tcphdr);
      break;
    case UDP:
      file.read((char *)&(packet.udph), sizeof(struct udphdr));
      header_size += sizeof(struct udphdr);
      break;
    }
    file.read((char *)(packet.payload), pcaprech.incl_len - header_size);
    packets.push_back(packet);
    file_size -= pcaprech.incl_len;
  }
  file.close();
  return packets;
}

void				LivePacketCapture::Write(std::string const &filename, packet_t packet)
{
    std::ofstream		file;
    
    LivePacketCapture::Read(packet);
    file.open(filename.c_str(), std::ofstream::out | std::ofstream::binary
	      | std::ofstream::app | std::ofstream::ate);
    file.flush();
    LivePacketCapture::PCAPWriteHeader(file, (int)(packet.size));    
    file.write((char *)&(packet.eth), sizeof(struct ethhdr));
    file.write((char *)&(packet.iph), sizeof(struct iphdr));

    switch (packet.iph.protocol) {
    case ICMP:
      file.write((char *)&(packet.icmph), sizeof(struct icmphdr));
      break;
    case TCP:
      file.write((char *)&(packet.tcph), sizeof(struct tcphdr));
      break;
    case UDP:
      file.write((char *)&(packet.udph), sizeof(struct udphdr));
      break;
    }  
    file.write((char *)(packet.payload), packet.paylen);
    file.flush();
    file.close();
}

std::string			LivePacketCapture::Read(packet_t packet)
{
  std::stringstream		infos;

  infos << LivePacketCapture::ReadEthernet(packet) << LivePacketCapture::ReadIP(packet);
  switch (packet.iph.protocol) {
  case ICMP:
    infos << LivePacketCapture::ReadICMP(packet);
    break;
  case TCP:
    infos << LivePacketCapture::ReadTCP(packet);
    break;
  case UDP:
    infos << LivePacketCapture::ReadUDP(packet);
    break;
  }  
  infos << LivePacketCapture::ReadPayload(packet);
  return infos.str();
}

std::string			LivePacketCapture::ReadEthernet(packet_t packet)
{
  std::stringstream		infos;
  
  infos << "Ethernet Header" << std::endl
  	<< "- Destination: " << std::hex << std::uppercase << (unsigned short)packet.eth.h_dest[0]
  	<< "." << (unsigned short)packet.eth.h_dest[1]
  	<< "." << (unsigned short)packet.eth.h_dest[2]
  	<< "." << (unsigned short)packet.eth.h_dest[3]
  	<< "." << (unsigned short)packet.eth.h_dest[4]
  	<< "." << (unsigned short)packet.eth.h_dest[5] << std::endl
  	<< "- Source: " << std::hex << std::uppercase << (unsigned short)packet.eth.h_source[0]
  	<< "." << (unsigned short)packet.eth.h_source[1]
  	<< "." << (unsigned short)packet.eth.h_source[2]
  	<< "." << (unsigned short)packet.eth.h_source[3]
  	<< "." << (unsigned short)packet.eth.h_source[4]
  	<< "." << (unsigned short)packet.eth.h_source[5] << std::endl
  	<< "- Protocol: " << std::dec << (unsigned short)packet.eth.h_proto << std::endl;
  return infos.str();
}


std::string			LivePacketCapture::ReadIP(packet_t packet)
{
  std::stringstream		infos;
  struct sockaddr_in		source, dest;

  memset(&source, 0, sizeof(struct sockaddr_in));
  memset(&dest, 0, sizeof(struct sockaddr_in));
  source.sin_addr.s_addr = packet.iph.saddr;
  dest.sin_addr.s_addr = packet.iph.daddr;

  infos << "IP Header" << std::endl
	<< "- IP Version: " << (unsigned int)packet.iph.version << std::endl
	<< "- IP Header Length: " << (unsigned int)packet.iph.ihl
	<< " DWORDS or " << (((unsigned int)packet.iph.ihl) * 4)
	<< " Bytes" << std::endl
	<< "- Type Of Service: " << (unsigned int)packet.iph.tos << std::endl
	<< "- IP Total Length: " << ntohs(packet.iph.tot_len)
	<< " Bytes(Size of Packet)" << std::endl
	<< "- Identification: " << ntohs(packet.iph.id) << std::endl
	<< "- TTL: " << (unsigned int)packet.iph.ttl << std::endl
	<< "- Protocol: " << (unsigned int)packet.iph.protocol << std::endl
	<< "- Checksum: " << ntohs(packet.iph.check) << std::endl
	<< "- Source IP: " << inet_ntoa(source.sin_addr) << std::endl
	<< "- Destination IP: " << inet_ntoa(dest.sin_addr) << std::endl;
  return infos.str();
}

std::string			LivePacketCapture::ReadICMP(packet_t packet)
{
  std::stringstream		infos;

  infos << "ICMP Header" << std::endl
	<< "- Type: " << (unsigned int)packet.icmph.type;
  if ((unsigned int)packet.icmph.type == 11)
    infos << " (TTL Expired)";
  else if ((unsigned int)packet.icmph.type == ICMP_ECHOREPLY)
    infos << " (ICMP Echo Reply)";
  infos << std::endl
	<< "- Code: " << (unsigned int)packet.icmph.code << std::endl
	<< "- Checksum: " << ntohs(packet.icmph.checksum) << std::endl;
  return infos.str();
}

std::string			LivePacketCapture::ReadTCP(packet_t packet)
{
    std::stringstream		infos;

    infos << "TCP Header" << std::endl
  	<< "- Source Port: " << ntohs(packet.tcph.source) << std::endl
  	<< "- Destination Port: " << ntohs(packet.tcph.dest) << std::endl
  	<< "- Sequence Number: " << ntohl(packet.tcph.seq) << std::endl
  	<< "- Acknowledge Number: " << ntohl(packet.tcph.ack_seq) << std::endl
  	<< "- Header Length: " << (unsigned int)packet.tcph.doff
  	<< " DWORDS or " << ((unsigned int)packet.tcph.doff * 4)
  	<< " BYTES" << std::endl
  	<< "- Urgent Flag: " << (unsigned int)packet.tcph.urg << std::endl
  	<< "- Acknowledgement Flag: " << (unsigned int)packet.tcph.ack << std::endl
  	<< "- Push Flag: " << (unsigned int)packet.tcph.psh << std::endl
  	<< "- Reset Flag: " << (unsigned int)packet.tcph.rst << std::endl
  	<< "- Synchronise Flag: " << (unsigned int)packet.tcph.syn << std::endl
  	<< "- Finish Flag: " << (unsigned int)packet.tcph.fin << std::endl
  	<< "- Window: " << ntohs(packet.tcph.window) << std::endl
  	<< "- Checksum: " << ntohs(packet.tcph.check) << std::endl
  	<< "- Urgent Pointer: " << ntohs(packet.tcph.urg_ptr) << std::endl;
  return infos.str();
}

std::string			LivePacketCapture::ReadUDP(packet_t packet)
{
  std::stringstream		infos;

  infos << "UDP Header" << std::endl
	<< "- Source Port: " << ntohs(packet.udph.source) << std::endl
	<< "- Destination Port: " << ntohs(packet.udph.dest) << std::endl
	<< "- UDP Length: " << ntohs(packet.udph.len) << std::endl
	<< "- UDP Checksum: " << ntohs(packet.udph.check) << std::endl;
  return infos.str();
}

std::string			LivePacketCapture::ReadPayload(packet_t packet)
{
  std::stringstream		infos;

  infos << "Data Payload" << std::endl
	<< packet.payload << std::endl;
  return infos.str();
}

LivePacketCapture::LivePacketCapture(std::string const &interface)
{
  if (interface.size() >= 16)
    throw std::string("Interface: Invalid name");

  struct ifreq			ifr;

  strcpy(ifr.ifr_name, interface.c_str());
  ifr.ifr_flags = IFF_UP | IFF_PROMISC | IFF_BROADCAST | IFF_RUNNING; // Search !
  if ((this->_raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    std::cerr << "Socket: " << std::strerror(errno) << std::endl;
  else if (ioctl(this->_raw_socket, SIOCSIFFLAGS, &ifr) < 0)
    throw std::string("Ioctl") + interface + ": " + std::strerror(errno);
}

LivePacketCapture::~LivePacketCapture()
{
  close(this->_raw_socket);
}

packet_t			LivePacketCapture::Capture() const
{
  packet_t			packet;
  u_char			buffer[4096];
  ssize_t			value;

  memset(&packet, 0, sizeof(packet_t));
  memset(buffer, 0, sizeof(buffer));
  if ((value = recv(this->_raw_socket, buffer, sizeof(buffer), 0)) < 0)
    throw std::string("Recvfrom: ") + std::strerror(errno);
  if (value > 0) {
    struct iphdr		*iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    unsigned short		iplen = iph->ihl * 4;
    ssize_t			header_size = sizeof(struct ethhdr) + iplen;
    
    memcpy(&(packet.eth), buffer, sizeof(struct ethhdr));
    memcpy(&(packet.iph), (buffer + sizeof(struct ethhdr)), iplen);
    
    switch (iph->protocol) {
    case ICMP:
      memcpy(&(packet.icmph), (buffer + header_size), sizeof(struct icmphdr));
      header_size += sizeof(struct icmphdr);
      break;
    case TCP:
      memcpy(&(packet.tcph), (buffer + header_size), sizeof(struct tcphdr));
      header_size += sizeof(struct tcphdr);
      break;
    case UDP:
      memcpy(&(packet.udph), (buffer + header_size), sizeof(struct udphdr));
      header_size += sizeof(struct udphdr);
      break;
    }
    packet.size = value;
    packet.paylen = value - header_size;
    memcpy(packet.payload, (buffer + header_size), packet.paylen);
    return packet;
  }
  return packet;
}

void				LivePacketCapture::PCAPWriteHeader(std::ofstream &file, int size)
{
  if (file.tellp() == 0) {
    pcap_hdr_t		pcaph;
    
    pcaph.magic_number = 0xA1B2C3D4;
    pcaph.version_major = 0x0002;
    pcaph.version_minor = 0x0004;
    pcaph.thiszone = 0x00000000;
    pcaph.sigfigs = 0x00000000;
    pcaph.snaplen = 0x0000FFFF;
    pcaph.network = 0x00000001;
    
    file.write((char *)&pcaph, sizeof(pcap_hdr_t));
  }
  
  pcaprec_hdr_t			pcaprech;
  struct timeval		tv;
  int				invert;
  
  if ((size * 256) < 0x00010000)
    invert = (((size * 256) & 0x0000FF00) >> 8) | (((size * 256) & 0x000000FF) << 8);
  else
    invert = (((size * 256) & 0x0000FF00) >> 8) | (((size * 256) & 0x000F0000) >> 8);
  
  gettimeofday(&tv, NULL);
  pcaprech.ts_sec = tv.tv_sec;
  pcaprech.ts_usec = tv.tv_usec;
  pcaprech.incl_len = invert;
  pcaprech.orig_len = invert;  
  file.write((char *)&pcaprech, sizeof(pcaprec_hdr_t));
}
