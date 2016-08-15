/*
 Pcap�ļ�ͷ24B���ֶ�˵����
 Magic��4B��0x1A 2B 3C 4D:������ʾ�ļ��Ŀ�ʼ
 Major��2B��0x02 00:��ǰ�ļ���Ҫ�İ汾��     
 Minor��2B��0x04 00��ǰ�ļ���Ҫ�İ汾��
 ThisZone��4B���صı�׼ʱ�䣻ȫ��
 SigFigs��4Bʱ����ľ��ȣ�ȫ��
 SnapLen��4B���Ĵ洢����    
 LinkType��4B��·����
 �������ͣ�
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
 Packet ��ͷ��Packet�������
 �ֶ�˵����
 Timestamp��ʱ�����λ����ȷ��seconds     
 Timestamp��ʱ�����λ����ȷ��microseconds
 Caplen����ǰ�������ĳ��ȣ���ץȡ��������֡���ȣ��ɴ˿��Եõ���һ������֡��λ�á�
 Len���������ݳ��ȣ�������ʵ������֡�ĳ��ȣ�һ�㲻����caplen����������º�Caplen��ֵ��ȡ�
 Packet ���ݣ��� Packet��ͨ��������·�������֡���������ݣ����Ⱦ���Caplen��������ȵĺ��棬���ǵ�ǰPCAP�ļ��д�ŵ���һ��Packet���ݰ���Ҳ�� ��˵��PCAP�ļ����沢û�й涨�����Packet���ݰ�֮����ʲô����ַ�������һ���������ļ��е���ʼλ�á�������Ҫ����һ��Packet��ȷ����
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