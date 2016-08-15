#define MAXSIZE 2000
int arrayLength=0;

typedef struct linkNode{
	char		srcip[20];
	int			visitcount;
	linkNode	*next;
}linkNode;
//Դ��ַ����

typedef struct arrayNode{
	char		destip[20];
	linkNode	*firstlinknode;
}arrayNode;
//Ŀ�ĵ�ַ����

void initArrayNode(arrayNode dest[]);
int searchArray(arrayNode dest[],char *destip,int arrayLength);
void upsetNode(arrayNode dest[],char *srcip,int i);
void destoryArray(arrayNode dest[],int arrayLength);


//�Խڵ�������г�ʼ��
void initArrayNode(arrayNode dest[])
{
	int i=0;
	for(;i<MAXSIZE;i++)
	{
		strcpy(dest[i].destip,"");
		dest[i].firstlinknode =NULL;
		/*dest[i].firstlinknode->next=NULL;
		strcpy(dest[i].firstlinknode->srcip,"");
		dest[i].firstlinknode->visitcount=0;*/
	}
}
//�������ң����½ڵ�����
int searchArray(arrayNode dest[],char *destip,int *arrayLength)
{
	if(strlen(destip)==0)
	{
		return -1;
	}
	else if(*arrayLength==0)
	{
		strcpy(dest[(*arrayLength)++].destip,destip);
		return (*arrayLength)-1;
	}
	else
	{
		int i=0;
		for(;i<*arrayLength;i++)
			if(strcmp(dest[i].destip,destip)==0)//����0��ʾ�����ַ�����ͬ����Ϊ1
				return i;
		if(i==*arrayLength)
		{
			strcpy(dest[(*arrayLength)++].destip,destip);
			return *arrayLength-1;
		}
	}
}

//������������µĽڵ�
void upsetNode(arrayNode dest[],char *srcip,int *i)
{
	if(*i!=-1)
	{
		linkNode *p=dest[*i].firstlinknode;
		while(p->srcip)//--�����������⣬����ѭ����--
		{
			if(strcmp(p->srcip,srcip)==0)//�жϣ��������������
				{
					p->visitcount++;
					return;
				}
			else
				p=p->next ;
			//printf("%s\t%s\t%d\n",p->srcip,srcip,p->visitcount);
			
		}
		if(!p)//��p�ǿյģ�Ҳ����˵���������������һ�飩-�������ͷ���뷨
		{
		  linkNode *s=(linkNode*)malloc(sizeof(linkNode));
		  strcpy(s->srcip,srcip);
		  s->visitcount=1;
		  s->next= dest[*i].firstlinknode;
		  printf("%s\t%d\t%s\n",s->srcip,s->visitcount,s->next);
	      dest[*i].firstlinknode=s;

		 
		}
	}
}




void destoryArray(arrayNode dest[],int arrayLength)
{
	int i=0;
	for(;i<arrayLength;i++)
	{
		linkNode *p=dest[i].firstlinknode;
		linkNode *s=p;
		while(p)
		{
			p=p->next;
			free(s);
			s=p;
		}
	}
}

