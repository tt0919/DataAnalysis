#define MAXSIZE 2000
int arrayLength=0;

typedef struct linkNode{
	char		srcip[20];
	int			visitcount;
	linkNode	*next;
}linkNode;
//源地址链表

typedef struct arrayNode{
	char		destip[20];
	linkNode	*firstlinknode;
}arrayNode;
//目的地址数组

void initArrayNode(arrayNode dest[]);
int searchArray(arrayNode dest[],char *destip,int arrayLength);
void upsetNode(arrayNode dest[],char *srcip,int i);
void destoryArray(arrayNode dest[],int arrayLength);


//对节点数组进行初始化
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
//遍历查找，更新节点数组
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
			if(strcmp(dest[i].destip,destip)==0)//等于0表示两个字符串相同否则为1
				return i;
		if(i==*arrayLength)
		{
			strcpy(dest[(*arrayLength)++].destip,destip);
			return *arrayLength-1;
		}
	}
}

//遍历链表插入新的节点
void upsetNode(arrayNode dest[],char *srcip,int *i)
{
	if(*i!=-1)
	{
		linkNode *p=dest[*i].firstlinknode;
		while(p->srcip)//--本部分有问题，无限循环中--
		{
			if(strcmp(p->srcip,srcip)==0)//判断，等于零则是相等
				{
					p->visitcount++;
					return;
				}
			else
				p=p->next ;
			//printf("%s\t%s\t%d\n",p->srcip,srcip,p->visitcount);
			
		}
		if(!p)//当p是空的（也就是说将本条链表遍历了一遍）-而后采用头插入法
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

