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
	//��������ָ�룬�����������е�������������
	pcap_if_t *alldevs;
	//��ǰ����������������
	pcap_if_t *d;
	//��ǰѭ�������
	int inum;
	//��ʼ����ǰ���������Ϊ0
	int i=0;
	//pcap�Ĳ������ݽṹָ��
	pcap_t *adhandle;
	//
	int res;
	//������Ϣ�ַ���
	char errbuf[PCAP_ERRBUF_SIZE];
	//ʱ��ṹ�����
	struct tm *ltime;
	//ʱ���ʽ���ַ���
	char timestr[16];
	//pcap�����ݰ�ͷָ��
	struct pcap_pkthdr *header;
	//��ǰ���������ݰ�
	const u_char *pkt_data;
	//����ʱ��,����
	time_t local_tv_sec;
		
    
	/* Retrieve the device list */
	//��ȡ�����豸�б�,���ʧ�ܾ����������Ϣ,����ɹ��Ͱ��豸����alldeves,�Ѵ������errbuf
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		return -1;
	}
    
    /* Print the list */
	//ѭ���оٳ����е�����,���Ұ�ѭ���ĵ�ǰ�������ڵ�ǰ������d��
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
	
	//���û��ѭ��������,��ô���������
    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }
    
	//��ӡ���˵�ѡ��,���û�ѡ���������
    printf("Enter the interface number (1-%d):",i);
    scanf("%d", &inum);
    
	//��������������Ų����б���,��ô���˳���
    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
	
    /* Jump to the selected adapter */
	//����ѡ�����������,���Ұ�������Ϊ��ǰ����d
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
    
	/* Open the adapter */
	//������,���ҰѴ����Ľ������adhandle��,����򿪴���,��ô�͹ر������б�
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
    
	//�������ȷ,�Ϳ�ʼ���һ����Ϣ֮��,��ӡ��������������Ϣ
    printf("\n%s\nlistening on %s...\n", pcap_lib_version(),d->description);
	
    /* At this point, we don't need any more the device list. Free it */
	//alldevs����ָ������Ѿ�������Ҫ��,�ͷ�����,ע��,��ʱ�Ĳ�����������d�Ѿ���֮�����adhandle����
    pcap_freealldevs(alldevs);
	
	/* Retrieve the packets */
	//��ʼ��adhandle�ж�ȡ����,���ص�����״̬����res��,���res���ڵ���0,�ͼ���,�����˳�
	//����res��״̬��:
	//  1 ��ȡ����
	//  0 ��ȡʱ�䳬ʱ.���������header��pkt_dataָ��ָ��ĵط���Ч(����ʹ��)
	// -1 if an error occurred
	// -2 if EOF was reached reading from an offline capture
/////////////////////////////////////////////////////////////////////�����￪ʼѭ������ 
	while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0){
		
		if(res == 0)
			/* Timeout elapsed */
			//�����ȡʱ�䳬ʱ,��ô�������ٶ�ȡ
			continue;
		//��ѡ��ARP���ݰ���Ҳ���ǵ�12��13���ֽ���0806�����������ݣ�Э�������ֶΣ�
		if (pkt_data[12] == 0x08 && pkt_data[13] == 0x00 && pkt_data[42]==0x02) {
			int qq ;
			qq = pkt_data[49];
			for (i=50;i<=52;i++){
				qq = qq<<8;
				qq = qq + pkt_data[i];
			}
			printf("QQ��Ϊ��%d",qq);
			printf("/n");
			//״̬
			int state; 
			state = pkt_data[45];
			state = state <<8;
			state = state + pkt_data[46];
			switch(state)
			{
				case 129:
					printf("���ڻ�ȡ����״̬");
					break;
				case 88:
					printf("��������QQȺ");
					break;
				case 23:
					printf("���ڽ�����Ϣ");
					break;
				case 181:
					printf("��ȡ���ں��ѵ�״̬");
					break;
				case 2:
					printf("������Ϣ");
					break;
				case 39:
					printf("��ȡ���ߺ���");
					break;
				case 29:
					printf("�ؼ����󣨲�֪������ʲô��");
					break;
				case 205:
					printf("����Ϊ��������");
					break;
				default :
					printf("δ֪"); 
			} 
		}
		
	}

	//���resΪ-1�Ļ�,���������ӿڳ�����,���ܼ�����,�Ѵ����ӡ�����Ϳ�����
	
	//���չر�adhandle��Ӧ���������ͷ���Դ
   pcap_close(adhandle);  
   return 0;
}

