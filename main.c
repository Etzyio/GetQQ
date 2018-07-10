#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "pcap.h"

int main()
{
	//声明链表指针，用来保存所有的网卡的描述符
	pcap_if_t *alldevs;
	//当前操作的网卡描述符
	pcap_if_t *d;
	//当前循环的序号
	int inum;
	//初始化当前网卡的序号为0
	int i=0;
	//pcap的操作数据结构指针
	pcap_t *adhandle;
	//
	int res;
	//错误信息字符串
	char errbuf[PCAP_ERRBUF_SIZE];
	//时间结构体变量
	struct tm *ltime;
	//时间格式的字符串
	char timestr[16];
	//pcap的数据包头指针
	struct pcap_pkthdr *header;
	//当前操作的数据包
	const u_char *pkt_data;
	//本地时间,毫秒
	time_t local_tv_sec;
		
    
	/* Retrieve the device list */
	//获取本地设备列表,如果失败就输出错误信息,如果成功就把设备放在alldeves,把错误放在errbuf
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		return -1;
	}
    
    /* Print the list */
	//循环列举出所有的网卡,并且把循环的当前网卡放在当前操作的d中
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
	
	//如果没有循环出网卡,那么就输出错误
    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }
    
	//打印出菜单选项,让用户选择网卡编号
    printf("Enter the interface number (1-%d):",i);
    scanf("%d", &inum);
    
	//如果输入的网卡编号不在列表中,那么就退出来
    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
	
    /* Jump to the selected adapter */
	//调到选择的那张网卡,并且把它设置为当前网卡d
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
    
	/* Open the adapter */
	//打开网卡,并且把代开的结果放在adhandle中,如果打开错误,那么就关闭网卡列表
	if ((adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
    
	//如果打开正确,就开始输出一句消息之后,打印出网卡的描述信息
    printf("\n%s\nlistening on %s...\n", pcap_lib_version(),d->description);
	
    /* At this point, we don't need any more the device list. Free it */
	//alldevs链表指针变量已经不再需要了,释放它们,注意,此时的操作网卡对象d已经打开之后放在adhandle中了
    pcap_freealldevs(alldevs);
	
	/* Retrieve the packets */
	//开始从adhandle中读取数据,返回的数据状态放在res中,如果res大于等于0,就继续,否则退出
	//其中res的状态有:
	//  1 读取正常
	//  0 读取时间超时.这种情况下header和pkt_data指针指向的地方无效(不能使用)
	// -1 if an error occurred
	// -2 if EOF was reached reading from an offline capture
/////////////////////////////////////////////////////////////////////从这里开始循环捕获 
	while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0){
		
		if(res == 0)
			/* Timeout elapsed */
			//如果读取时间超时,那么就重新再读取
			continue;
		//挑选出ARP数据包，也就是第12、13个字节是0806的特征的数据（协议类型字段）
		if (pkt_data[12] == 0x08 && pkt_data[13] == 0x00 && pkt_data[42]==0x02) {
			int qq ;
			qq = pkt_data[49];
			for (i=50;i<=52;i++){
				qq = qq<<8;
				qq = qq + pkt_data[i];
			}
			printf("QQ号为：%d",qq);
			printf("/n");
			//状态
			int state; 
			state = pkt_data[45];
			state = state <<8;
			state = state + pkt_data[46];
			switch(state)
			{
				case 129:
					printf("正在获取好友状态");
					break;
				case 88:
					printf("正在下载QQ群");
					break;
				case 23:
					printf("正在接收消息");
					break;
				case 181:
					printf("获取组内好友的状态");
					break;
				case 2:
					printf("心跳消息");
					break;
				case 39:
					printf("获取在线好友");
					break;
				case 29:
					printf("关键请求（不知在请求什么）");
					break;
				case 205:
					printf("可能为发送数据");
					break;
				default :
					printf("未知"); 
			} 
		}
		
	}

	//如果res为-1的话,表明网卡接口出问题,不能继续了,把错误打印出来就可以了
	
	//最终关闭adhandle对应的网卡，释放资源
   pcap_close(adhandle);  
   return 0;
}

