#ifndef _LIVEPACKETCAPTURE_HPP_
# define _LIVEPACKETCAPTURE_HPP_

# include <sys/stat.h>
# include <sys/time.h>
# include <fstream>

# include <vector>
# include <string>
# include <sstream>

# include <sys/types.h>
# include <ifaddrs.h>

# include <sys/socket.h>
# include <arpa/inet.h>

# include <net/ethernet.h>
# include <netinet/ip_icmp.h>
# include <netinet/udp.h>
# include <netinet/tcp.h>

# include <sys/ioctl.h>
# include <net/if.h>

# include <netinet/ip.h>

# include <unistd.h>

# include <linux/if_packet.h>

# define ICMP				(1)
# define TCP				(6)
# define UDP				(17)

typedef struct				pcap_hdr_s {
  uint32_t				magic_number;
  uint16_t				version_major;
  uint16_t				version_minor;
  int32_t				thiszone;     
  uint32_t				sigfigs;      
  uint32_t				snaplen;      
  uint32_t				network;      
}					pcap_hdr_t;

typedef struct				pcaprec_hdr_s {
  uint32_t				ts_sec;         
  uint32_t				ts_usec;        
  uint32_t				incl_len;       
  uint32_t				orig_len;       
}					pcaprec_hdr_t;

typedef struct				packet_s {
  struct ethhdr				eth;
  struct iphdr				iph;
  struct icmphdr			icmph;
  struct tcphdr				tcph;
  struct udphdr				udph;
  u_char				payload[4096];
  ssize_t				paylen;
  ssize_t				size;
}					packet_t;

class					LivePacketCapture
{
public:
  static std::vector<std::string>	Interfaces();

  static std::vector<packet_t>		Load(std::string const &filename);
  static void				Write(std::string const &filename, packet_t packet);
  static std::string			Read(packet_t packet);

  static std::string			ReadEthernet(packet_t packet);
  static std::string			ReadIP(packet_t packet);
  static std::string			ReadICMP(packet_t packet);
  static std::string			ReadTCP(packet_t packet);
  static std::string			ReadUDP(packet_t packet);
  static std::string			ReadPayload(packet_t packet);

  LivePacketCapture(std::string const &interface);
  virtual ~LivePacketCapture();

  packet_t				Capture() const;
private:
  static void				PCAPWriteHeader(std::ofstream &file, int size);

  int					_raw_socket;
  
  LivePacketCapture() {};
  LivePacketCapture(LivePacketCapture const &lpc) {};
  LivePacketCapture &operator=(LivePacketCapture const &lpc) {};
};

#endif // !_LIVEPACKETCAPTURE_HPP_
