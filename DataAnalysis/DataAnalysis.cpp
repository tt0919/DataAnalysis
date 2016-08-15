// DataAnalysis.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include<stdio.h>
#include<stdlib.h>
#include<Winsock2.h> 
#include<string.h>
#include<time.h>
#include <Ws2tcpip.h>

#include"Header.h"
#include"linknode.h"
#pragma  comment(lib,"WS2_32.lib")
void readFile(char *filename,char *outfile,char *storefile);
void search(arrayNode dest[],int arrayLength,char *storefile);

int _tmain(int argc, _TCHAR* argv[])
{
	//char filename[]="C:\\Users\\Administrator\\Desktop\\ddos.pcap";
	char filename[]="D:\\201301普通正常未被攻击流量\\B\\pcap\\equinix-sanjose.dirB.20130117-125904.UTC.anon.pcap";
	char outfile[]="C:\\Users\\Administrator\\Desktop\\1-ping.txt";
	char storefile[]="C:\\Users\\Administrator\\Desktop\\2-ping.txt";
	
	
	readFile(filename,outfile,storefile);

	

	system("pause");
	return 0;
}



void readFile(char *filename,char *outfile,char *storefile)
{
	pcap_file_header pfh;
	pcap_header ph;
	ipheader    iphr;
	tcpheader   tcphr;
	udpheader   udphr;
	icmpheader  icmphr;
	fivetuple   tuple;
	u_long      count=0;
	u_short     datalen=0;
	int			SZFH=0;
	u_long		sumlen=0;
	u_long		qc_sumlen=0;
	arrayNode	dest[10000];
	//初始化目的地址数组
	initArrayNode(dest);
	char datastr[256],protocol[8],srcip[20],destip[20];	
	int  ipheadlen,srcport,destport;
	FILE *in,*out,*outstore;
	if((in=fopen(filename,"rb"))==NULL)
	{
		printf("%s can not open!\n",filename);
		exit(-1);
	}
	remove(outfile);
	remove(storefile);
	out=fopen(outfile,"w+");
	outstore=fopen(storefile,"w+");
	fread(&pfh,sizeof(pcap_file_header),1,in);
	printf("%10s%16s%24s\n","ID ","SrcIP ","DestIP ");


	while(!feof(in)&&count<100)//控制读取行数为2000
//	while(!feof(in))
	{		
		count++;
		fread(&ph,sizeof(pcap_header),1,in);
		memset(datastr,0,sizeof(datastr));
		fread(datastr,ph.capture_len ,1,in);
		memcpy(&iphr,datastr,20);
		ipheadlen=(iphr.version_headlen&0x0f)*4;
		inet_ntop(AF_INET,(void *)&iphr.src_ip,srcip,sizeof(srcip));
		inet_ntop(AF_INET,(void *)&iphr.dest_ip,destip,sizeof(destip));
		strcpy(tuple.srcip ,srcip);
		strcpy(tuple.destip ,destip);

		if(((iphr.version_headlen &0xf0)>>4)!=4)
		{


			printf("\nversion :%d\nprotocol is %d\n",(iphr.version_headlen &0xf0)>>4,iphr.protocol);
			printf("不是IPv4版本\n");
			continue;
		}
		
		switch(iphr.protocol)
		{       
			case 1: 
				strcpy(protocol,"ICMP");
				if(ipheadlen+8<=ph.capture_len)
				{
					memcpy(&icmphr,datastr+ipheadlen,8);
					srcport=destport=0;
					/*
					switch(icmphr.icmptype)
					{
					  case 0: printf("echo request\n");break;
					  case 3: printf("destination unreachable\n");break;
					  case 4: printf("source quench\n");break;
					  case 5: printf("redirect routing\n");break;
					  case 8: printf("echo ack\n");break;
					  case 11: printf("time exceeded\n");break;
					  case 12: printf("parameter\n");break;
					  case 13: printf("timestamp request\n");break;
					  case 14: printf("timestamp echo");break;
					  default: printf("default icmptype");
					}
					*/
				}
				break;
			case 2: 
				strcpy(protocol,"IGMP");
				srcport=destport=0;
				break;
			case 6:
				
				strcpy(protocol,"TCP");
				if(ipheadlen+20<=ph.capture_len)
				{
					memcpy(&tcphr,datastr+ipheadlen,20);
					srcport=tcphr.src_port;
				    destport=tcphr.dest_port;
				}
				break;
			case 8: 
				strcpy(protocol,"EGP");
				srcport=destport=0;
				break;
			case 9:
				strcpy(protocol,"IGP");
				srcport=destport=0;
				break;
			case 17: 
				strcpy(protocol,"UDP");
				if(ipheadlen+8<=ph.capture_len)
				{
					memcpy(&udphr,datastr+ipheadlen,8);
					srcport=udphr.src_port;
					destport=udphr.dest_port;
				}
				break;
			case 41:
				strcpy(protocol,"IPv6");
				srcport=destport=0;
				break;
			case 89: 
				strcpy(protocol,"OSPF");
				srcport=destport=0;
				break;
			default:
				strcpy(protocol,"default");
				srcport=destport=0;
		}
		
		printf("%8d%22s%22s\n",count,srcip,destip);
		


		strcpy(tuple.protocol,protocol); 
		tuple.srcport=srcport;
		tuple.destport=destport;
		//fprintf(out,"%8d%22s%22s\n",count,tuple.srcip,tuple.destip);
		fprintf(out,"%8d%22s%22s\n",count,tuple.srcip,tuple.destip);
		

		SZFH=searchArray(dest,destip,&arrayLength);
		printf("SZFH=%d\narrayLength=%d\n",SZFH,arrayLength);
		upsetNode(dest,srcip,&SZFH);
		
	}	
	//遍历并且输出（存储）整个结构
	for(int i=0;i<arrayLength;i++)
	{
		sumlen=0;
		qc_sumlen=0;
		printf("\ndestip=%s\n\n",dest[i].destip);
		fprintf(outstore,"\ndestip=%s\n\n",dest[i].destip);
		linkNode *p=dest[i].firstlinknode;
		while(p)
		{
			printf("srcip=%s count=%d\t",p->srcip,p->visitcount);
			fprintf(outstore,"srcip=%s count=%d\t",p->srcip,p->visitcount);
			
			sumlen+=p->visitcount;
			qc_sumlen+=1;

			p=p->next ;
		}
		fprintf(outstore,"\nsumlen=%d\tqc_sumlen=%d\n",sumlen,qc_sumlen);
		fprintf(outstore,"\n\n==========================================================\n");
		printf("\n\n==========================================================\n");
	}

	destoryArray(dest,arrayLength);
	fclose(in);
	fclose(out);
	fclose(outstore);
}



/*
		ch=fgetc(in);
		sprintf(s,"%02x\t",ch);
		count++;
		fputs(s,out);
		if(count%16==0)
			fputs("\n",out);
*/
