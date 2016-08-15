/*
 Pcap文件头24B各字段说明：
 Magic：4B：0x1A 2B 3C 4D:用来标示文件的开始
 Major：2B，0x02 00:当前文件主要的版本号     
 Minor：2B，0x04 00当前文件次要的版本号
 ThisZone：4B当地的标准时间；全零
 SigFigs：4B时间戳的精度；全零
 SnapLen：4B最大的存储长度    
 LinkType：4B链路类型
 常用类型：
 0            BSD loopback devices, except for later OpenBSD
 1            Ethernet, and Linux loopback devices
 6            802.5 Token Ring
 7            ARCnet
 8            SLIP
 9            PPP
 */

typedef struct pacp_file_header{
	unsigned int     magic;
	unsigned short   version_major;
	unsigned short   version_minor;
	unsigned int     thiszone;
	unsigned int	 sigfigs;
	unsigned int     snaplen;
	unsigned int     linktype;
}pcap_file_header;

/*
 Packet 包头和Packet数据组成
 字段说明：
 Timestamp：时间戳高位，精确到seconds     
 Timestamp：时间戳低位，精确到microseconds
 Caplen：当前数据区的长度，即抓取到的数据帧长度，由此可以得到下一个数据帧的位置。
 Len：离线数据长度：网络中实际数据帧的长度，一般不大于caplen，多数情况下和Caplen数值相等。
 Packet 数据：即 Packet（通常就是链路层的数据帧）具体内容，长度就是Caplen，这个长度的后面，就是当前PCAP文件中存放的下一个Packet数据包，也就 是说：PCAP文件里面并没有规定捕获的Packet数据包之间有什么间隔字符串，下一组数据在文件中的起始位置。我们需要靠第一个Packet包确定。
 */

typedef struct timestamp{
	unsigned int  timestamp_s;
	unsigned int  timestamp_ms;
}timestamp;


typedef struct pcap_header{
	timestamp     ts;
	unsigned int  capture_len;
	unsigned int  len;
}pcap_header;


typedef struct frameheader{
	unsigned char  dest_mac[6];
	unsigned char  src_mac[6];
	unsigned short frametype;
}frameheader;


typedef struct ipheader{
	unsigned char   version_headlen;
	unsigned char   tos;
	unsigned short  total_len;
	unsigned short  id;
	unsigned short  flag:3;
	unsigned short  frag_off:13;
	unsigned char   ttl;
	unsigned char   protocol;
	unsigned short  checksum;
	struct in_addr   src_ip;
	struct in_addr   dest_ip;
}ipheader;


typedef struct tcpheader{
	unsigned short src_port;
	unsigned short dest_port;
	unsigned int   seq_no;
	unsigned int   ack_no;
	unsigned short headlen_reserved_flag;
	unsigned short wnd_size;
	unsigned short checksum;
	unsigned short urgpointer;
}tcpheader;


typedef struct udpheader{
	unsigned short src_port;
	unsigned short dest_port;
	unsigned short headlen;
	unsigned short checksum;
}udpheader;


typedef struct icmpheader{
	unsigned char   icmptype;
	unsigned char   code;
	unsigned short  checksum;
	unsigned short  identifier;
	unsigned short  seq;
}icmpheader;


typedef struct fivetuple
{
	char srcip[20];
	char destip[20];
	char protocol[8];
	unsigned int srcport;
	unsigned int destport;
}fivetuple;

typedef struct node
{
	char	ip[20];
	node	*next;
	int		count;
}Node,*PNode;