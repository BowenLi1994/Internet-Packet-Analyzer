//
//  main.cpp
//  pro_final
//
//  Created by Bowen Li on 12/5/17.
//  Copyright © 2017 Bowen Li. All rights reserved.
//
#include <iostream>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <algorithm>
using namespace std;


/*****************Data Struct************/

struct mac_header{
    uint8_t dest_mac[6];//destination mac address
    uint8_t source_mac[6];//source mac address
    uint8_t ethernet_type[2];// ethernet_type
};

struct ip_header{
    uint8_t version_header;
    uint8_t TOS;
    uint8_t length[2];
    uint8_t ID[2];
    uint8_t flag[2];
    uint8_t TTL;
    uint8_t type;
    uint8_t header_checksum[2];
    uint8_t source_ip[4];
    uint8_t dest_ip[4];
    uint8_t optional[4];
    int version;
    int size;
    int flag1;
    int flag2;
    int offset;
    
};


struct arp_header{
    uint8_t fha[2];        /* format of hardware address */
    uint8_t fpa[2];    /* format of protocol address */
    uint8_t length_ha;    /* length of hardware address */
    uint8_t length_pa;    /* length of protocol address */
    uint8_t op[2];     /* ARP/RARP operation */
    
    uint8_t source_ha[6];    /* sender hardware address */
    uint8_t source_ip[4];    /* sender protocol address */
    uint8_t dest_ha[6];    /* target hardware address */
    uint8_t dest_ip[4];    /* target protocol address */
};


struct tcp_header{
    uint8_t source_port[2];
    uint8_t dest_port[2];
    uint8_t sequence_number[4];
    uint8_t ack_number[4];
    uint8_t window[2];
    uint8_t checksum[2];
    uint8_t urgent_pointer[2];
    int data_offset;
    int reserved;
    int UGR;
    int ACK;
    int PSH;
    int RST;
    int SYN;
    int FIN;
};

struct udp_header{
    uint8_t source_port[2];
    uint8_t dest_port[2];
    uint8_t length[2];
    uint8_t checksome[2];
};

struct icmp_header{
    uint8_t type;
    uint8_t code;
    uint8_t checksum[2];
    uint8_t ID[2];
    uint8_t sequence_number[2];
};

struct ethernet_frame{
    uint32_t size;
    struct mac_header mach;
    struct arp_header arph;
    struct ip_header iph;
    struct tcp_header tcph;
    struct udp_header udph;
    struct icmp_header icmph;
    uint8_t frame_data[1522];
    char type[10];
    int broadcast;
    int pkt_id;
};

/****************CHange 1 bytes to 8 bits**********************/
void binary(int a, int* array) {
    int i = 0;
    for (i = 0; i < 8; i++) {
        array[7 - i] = a % 2;
        a /= 2;
    }
}

/*****************Get Enthernet Head*****************************/
void get_ethernet_header(struct ethernet_frame *frame,int no){
    
    
    int ip1=0X08;
    int ip2=0X00;
    int arp1=0X08;
    int arp2=0X06;
    for(int i=0;i<no;i++){
        for(int m=0;m<6;m++){
            frame[i].mach.dest_mac[m]=frame[i].frame_data[m];
            frame[i].mach.source_mac[m]=frame[i].frame_data[m+6];
        }
        frame[i].mach.ethernet_type[0]=frame[i].frame_data[12];
        frame[i].mach.ethernet_type[1]=frame[i].frame_data[13];
        
        int broadcast_flag=1;
        for(int m=0;m<6;m++){
            if(frame[i].mach.dest_mac[m]!=0Xff)
                broadcast_flag=0;
        }
        if(broadcast_flag==1){
            frame[i].broadcast=1;
        }
        if(frame[i].mach.ethernet_type[0]==ip1&&frame[i].mach.ethernet_type[1]==ip2){
            strcpy(frame[i].type,"ip");
        }
        else if(frame[i].mach.ethernet_type[0]==arp1&&frame[i].mach.ethernet_type[1]==arp2){
            strcpy(frame[i].type,"arp");
        }
        else strcpy(frame[i].type,"other");
        
        
    }
    
    
}


/****************************Get IP Header**********************/
void get_ip_header(struct ethernet_frame *frame,int no){
    for(int i=0;i<no;i++){
        if(strcmp(frame[i].type, "ip")==0){
            frame[i].iph.version_header=frame[i].frame_data[14];
            frame[i].iph.TOS=frame[i].frame_data[15];
            frame[i].iph.length[0]=frame[i].frame_data[16];
            frame[i].iph.length[1]=frame[i].frame_data[17];
            frame[i].iph.ID[0]=frame[i].frame_data[18];
            frame[i].iph.ID[1]=frame[i].frame_data[19];
            frame[i].iph.flag[0]=frame[i].frame_data[20];
            frame[i].iph.flag[1]=frame[i].frame_data[21];
            frame[i].iph.TTL=frame[i].frame_data[22];
            frame[i].iph.type=frame[i].frame_data[23];
            
            frame[i].iph.header_checksum[0]=frame[i].frame_data[24];
            frame[i].iph.header_checksum[1]=frame[i].frame_data[25];
            for(int x=0;x<4;x++){
                frame[i].iph.source_ip[x]=frame[i].frame_data[26+x];
                frame[i].iph.dest_ip[x]=frame[i].frame_data[30+x];
            }
            if(frame[i].iph.type==17) {strcpy(frame[i].type,"udp"); }
            else if(frame[i].iph.type==6) {strcpy(frame[i].type,"tcp"); }
            else if(frame[i].iph.type==1) {strcpy(frame[i].type,"icmp"); }
            else {strcpy(frame[i].type,"otherip");}
            int ipheader[8];
            binary(frame[i].iph.version_header, ipheader);
            frame[i].iph.version=ipheader[3]+ipheader[2]*2+ipheader[1]*4+ipheader[0]*8;
            frame[i].iph.size=(ipheader[7]+ipheader[6]*2+ipheader[5]*4+ipheader[4]*8)*4;
            int header1[8];
            binary(frame[i].iph.flag[0], header1);;
            frame[i].iph.flag1=header1[1];
            frame[i].iph.flag2=header1[2];
            frame[i].iph.offset=(header1[3]*16+header1[4]*8+header1[5]*4+header1[6]*2+header1[7])*256+frame[i].iph.flag[1];
        }
    }
}

/*******************************Get ARP Header******************************/
void get_arp_header(struct ethernet_frame *frame,int no){
    for(int i=0;i<no;i++){
        if(strcmp(frame[i].type, "arp")==0){
            frame[i].arph.fha[0]=frame[i].frame_data[14];
            frame[i].arph.fha[1]=frame[i].frame_data[15];
            frame[i].arph.fpa[0]=frame[i].frame_data[16];
            frame[i].arph.fha[1]=frame[i].frame_data[17];
            frame[i].arph.length_ha=frame[i].frame_data[18];
            frame[i].arph.length_pa=frame[i].frame_data[19];
            frame[i].arph.op[0]=frame[i].frame_data[20];
            frame[i].arph.op[1]=frame[i].frame_data[21];
            for(int x=0;x<6;x++){
                frame[i].arph.source_ha[x]=frame[i].frame_data[22+x];
                frame[i].arph.dest_ha[x]=frame[i].frame_data[32+x];
            }
            for(int x=0;x<4;x++){
                frame[i].arph.source_ip[x]=frame[i].frame_data[28+x];
                frame[i].arph.dest_ip[x]=frame[i].frame_data[38+x];
            }
            
            
            
        }
    }
}

/*******************************Get UDP Header******************************/
void get_udp_header(struct ethernet_frame *frame,int no){
    for(int i=0;i<no;i++){
        if(strcmp(frame[i].type, "udp")==0){
            
            int ipheader[8];
            binary(frame[i].iph.version_header, ipheader);
            int header_size=(ipheader[7]+ipheader[6]*2+ipheader[5]*4+ipheader[4]*8)*4;
            //printf("%d\n",frame[i].iph.version_header);
            //printf("%d\n",header_size);
            frame[i].udph.source_port[0]=frame[i].frame_data[14+header_size];
            frame[i].udph.source_port[1]=frame[i].frame_data[14+header_size+1];
            frame[i].udph.dest_port[0]=frame[i].frame_data[14+header_size+2];
            frame[i].udph.dest_port[1]=frame[i].frame_data[14+header_size+3];
            frame[i].udph.length[0]=frame[i].frame_data[14+header_size+4];
            frame[i].udph.length[1]=frame[i].frame_data[14+header_size+5];
            frame[i].udph.checksome[0]=frame[i].frame_data[14+header_size+6];
            frame[i].udph.checksome[1]=frame[i].frame_data[14+header_size+7];
        }
    }
}
/*******************************Get TCP Header******************************/
void get_tcp_header(struct ethernet_frame *frame,int no){
    for(int i=0;i<no;i++){
        if(strcmp(frame[i].type, "tcp")==0){
            
            int ipheader[8];
            binary(frame[i].iph.version_header, ipheader);
            int header_size=(ipheader[7]+ipheader[6]*2+ipheader[5]*4+ipheader[4]*8)*4;
            frame[i].tcph.source_port[0]=frame[i].frame_data[14+header_size];
            frame[i].tcph.source_port[1]=frame[i].frame_data[14+header_size+1];
            frame[i].tcph.dest_port[0]=frame[i].frame_data[14+header_size+2];
            frame[i].tcph.dest_port[1]=frame[i].frame_data[14+header_size+3];
            for(int m=0;m<4;m++){
                frame[i].tcph.sequence_number[m]=frame[i].frame_data[18+frame[i].iph.size+m];
                frame[i].tcph.ack_number[m]=frame[i].frame_data[22+header_size+m];
            }
            uint8_t temp1=frame[i].frame_data[26+header_size];
            uint8_t temp2=frame[i].frame_data[27+header_size];
            int header1[8],header2[8];
            binary(temp1, header1);
            binary(temp2, header2);
            frame[i].tcph.data_offset=header1[0]*8+header1[1]*4+header1[2]*2+header1[3]*1;
            frame[i].tcph.reserved=header1[4]*32+header1[5]*16+header1[6]*8+header1[7]*4+header2[0]*2+header2[1];
            frame[i].tcph.UGR=header2[2];
            frame[i].tcph.ACK=header2[3];
            frame[i].tcph.PSH=header2[4];
            frame[i].tcph.RST=header2[5];
            frame[i].tcph.SYN=header2[6];
            frame[i].tcph.FIN=header2[7];
            frame[i].tcph.window[0]=frame[i].frame_data[28+header_size];
            frame[i].tcph.window[1]=frame[i].frame_data[29+header_size];
            frame[i].tcph.checksum[0]=frame[i].frame_data[30+header_size];
            frame[i].tcph.checksum[1]=frame[i].frame_data[31+header_size];
            frame[i].tcph.urgent_pointer[0]=frame[i].frame_data[32+header_size];
            frame[i].tcph.urgent_pointer[1]=frame[i].frame_data[33+header_size];
        }
    }
}
/*******************************Get ICMP Header******************************/
void get_icmp_header(struct ethernet_frame *frame,int no){
    for(int i=0;i<no;i++){
        if(strcmp(frame[i].type, "icmp")==0){
            
            int ipheader[8];
            binary(frame[i].iph.version_header, ipheader);
            int header_size=(ipheader[7]+ipheader[6]*2+ipheader[5]*4+ipheader[4]*8)*4;
            frame[i].icmph.type=frame[i].frame_data[14+header_size];
            frame[i].icmph.code=frame[i].frame_data[14+header_size+1];
            frame[i].icmph.checksum[0]=frame[i].frame_data[14+header_size+2];
            frame[i].icmph.checksum[1]=frame[i].frame_data[14+header_size+3];
            frame[i].icmph.ID[0]=frame[i].frame_data[14+header_size+4];
            frame[i].icmph.ID[1]=frame[i].frame_data[14+header_size+5];
            frame[i].icmph.sequence_number[0]=frame[i].frame_data[14+header_size+6];
            frame[i].icmph.sequence_number[1]=frame[i].frame_data[14+header_size+7];
            //std::cout<<frame[i].icmph.type<<"\n";
        }
    }
}
/*********************************The Function of No flag******************/
void no_flag(struct ethernet_frame *frame,int no){
    int no_ip=0;
    int no_arp=0;
    int no_broadcast=0;
    int no_other=0;
    int no_udp=0;
    int no_tcp=0;
    int no_icmp=0;
    int no_other_ip=0;
    
    for(int i=0;i<no;i++){
        if(frame[i].broadcast==1){
            no_broadcast++;
        }
        if(strcmp(frame[i].type, "arp")==0){
            no_arp++;
        }
        if(strcmp(frame[i].type, "udp")==0){
            no_udp++;
            no_ip++;
        }
        if(strcmp(frame[i].type, "tcp")==0){
            no_tcp++;
            no_ip++;
        }
        if(strcmp(frame[i].type, "icmp")==0){
            no_icmp++;
            no_ip++;
        }
        if(strcmp(frame[i].type, "otherip")==0){
            no_other_ip++;
            no_ip++;
        }
        if(strcmp(frame[i].type, "other")==0){
            no_other++;
            
        }
        
    }
    printf("Ethernet frames:        %d\n",no);
    printf("Ethernet broadcast:     %d\n",no_broadcast);
    printf("  ARP packets:          %d\n",no_arp);
    printf("  IP packets:           %d\n",no_ip);
    printf("    UDP packets:        %d\n",no_udp);
    printf("    TCP packets:        %d\n",no_tcp);
    printf("    ICMP packets:       %d\n",no_icmp);
    printf("    other IP packets:   %d\n",no_other_ip);
    printf("  other packets:        %d\n",no_other);
    /*cout <<"Ethernet frames:     "<<no<<"\n";
    cout <<"Ethernet broadcast:     "<< no_broadcast<<"\n";
    cout <<"  ARP packets:         "<<no_arp<<"\n";
    cout <<"  IP packets:         "<<no_ip<<"\n";
    cout <<"    UDP packets:     "<< no_udp<<"\n";
    cout <<"    TCP packets:     "<< no_tcp<<"\n";
    cout <<"    ICMP packets:    "<< no_icmp<<"\n";
    cout <<"    other IP packets:     "<< no_other_ip<<"\n";
    cout <<"  other packets:     "<< no_other<<"\n";*/
}
/*********************************The Function of -v flag******************/
void v_flag(struct ethernet_frame *frame,int no){
    for(int i=0;i<no;i++){
        
        if(strcmp(frame[i].type, "other")==0){
            printf("(unknown packet) ");
            printf("(%x:%x:%x:%x:%x:%x, ",frame[i].mach.dest_mac[0],frame[i].mach.dest_mac[1],frame[i].mach.dest_mac[2],frame[i].mach.dest_mac[3],frame[i].mach.dest_mac[4],frame[i].mach.dest_mac[5]);
            printf("%x:%x:%x:%x:%x:%x, ",frame[i].mach.source_mac[0],frame[i].mach.source_mac[1],frame[i].mach.source_mac[2],frame[i].mach.source_mac[3],frame[i].mach.source_mac[4],frame[i].mach.source_mac[5]);
            printf("%x:%x)\n",frame[i].mach.ethernet_type[0],frame[i].mach.ethernet_type[1]);
        }
        /*****************************/
        else if(strcmp(frame[i].type, "arp")==0){
            //printf("%02X\n",frame[i].iph.version_header);
            //cout<<frame[i].iph.version_header<<"\n";
            if(frame[i].broadcast==1){
                printf("%d.%d.%d.%d -> ",frame[i].arph.source_ip[0],frame[i].arph.source_ip[1],frame[i].arph.source_ip[2],frame[i].arph.source_ip[3]);
                printf("(broadcast) (ARP) who is");
                printf(" %d.%d.%d.%d\n",frame[i].arph.dest_ip[0],frame[i].arph.dest_ip[1],frame[i].arph.dest_ip[2],frame[i].arph.dest_ip[3]);
            }
            
            
            
            else if(frame[i].arph.op[0]==0&&frame[i].arph.op[1]==2){
                printf("%d.%d.%d.%d -> ",frame[i].arph.source_ip[0],frame[i].arph.source_ip[1],frame[i].arph.source_ip[2],frame[i].arph.source_ip[3]);
                printf("%d.%d.%d.%d ",frame[i].arph.dest_ip[0],frame[i].arph.dest_ip[1],frame[i].arph.dest_ip[2],frame[i].arph.dest_ip[3]);
                printf("(ARP) ");
                printf("%d.%d.%d.%d's hardware address is ",frame[i].arph.source_ip[0],frame[i].arph.source_ip[1],frame[i].arph.source_ip[2],frame[i].arph.source_ip[3]);
                printf("%x:%x:%x:%x:%x:%x\n",frame[i].arph.dest_ha[0],frame[i].arph.source_ha[1],frame[i].arph.source_ha[2],frame[i].arph.source_ha[3],frame[i].arph.source_ha[4],frame[i].arph.source_ha[5]);
            }
            else{
                printf("%d.%d.%d.%d -> ",frame[i].arph.source_ip[0],frame[i].arph.source_ip[1],frame[i].arph.source_ip[2],frame[i].arph.source_ip[3]);
                printf("%d.%d.%d.%d ",frame[i].arph.dest_ip[0],frame[i].arph.dest_ip[1],frame[i].arph.dest_ip[2],frame[i].arph.dest_ip[3]);
                printf("(ARP) who is ");
                printf("%d.%d.%d.%d\n",frame[i].arph.dest_ip[0],frame[i].arph.dest_ip[1],frame[i].arph.dest_ip[2],frame[i].arph.dest_ip[3]);
            }
        }
        
        
        
        else if(strcmp(frame[i].type, "udp")==0){
            if(frame[i].broadcast==2){
                printf("%d.%d.%d.%d ->",frame[i].iph.source_ip[0],frame[i].iph.source_ip[1],frame[i].iph.source_ip[2],frame[i].iph.source_ip[3]);
                printf("(broadcast)(UDP) who is %d.%d.%d.%d",frame[i].iph.dest_ip[0],frame[i].iph.dest_ip[1],frame[i].iph.dest_ip[2],frame[i].iph.dest_ip[3]);
                printf("sourceport=%d ",frame[i].udph.source_port[0]*256+frame[i].udph.source_port[1]);
                printf("destport=%d\n",frame[i].udph.dest_port[0]*256+frame[i].udph.dest_port[1]);
            }
            else{
            printf("%d.%d.%d.%d -> ",frame[i].iph.source_ip[0],frame[i].iph.source_ip[1],frame[i].iph.source_ip[2],frame[i].iph.source_ip[3]);
            printf("%d.%d.%d.%d (UDP) ",frame[i].iph.dest_ip[0],frame[i].iph.dest_ip[1],frame[i].iph.dest_ip[2],frame[i].iph.dest_ip[3]);
            printf("sourceport = %d ",frame[i].udph.source_port[0]*256+frame[i].udph.source_port[1]);
            printf("destport = %d\n",frame[i].udph.dest_port[0]*256+frame[i].udph.dest_port[1]);
            }
            
        }
        else if(strcmp(frame[i].type, "tcp")==0){
            if(frame[i].broadcast==2){
                printf("%d.%d.%d.%d -> ",frame[i].iph.source_ip[0],frame[i].iph.source_ip[1],frame[i].iph.source_ip[2],frame[i].iph.source_ip[3]);
                printf("(broadcast)(TCP)who is %d.%d.%d.%d ",frame[i].iph.dest_ip[0],frame[i].iph.dest_ip[1],frame[i].iph.dest_ip[2],frame[i].iph.dest_ip[3]);
                printf("sourceport=%d ",frame[i].tcph.source_port[0]*256+frame[i].tcph.source_port[1]);
                printf("destport=%d\n",frame[i].tcph.dest_port[0]*256+frame[i].tcph.dest_port[1]);
            }
            else{
            printf("%d.%d.%d.%d -> ",frame[i].iph.source_ip[0],frame[i].iph.source_ip[1],frame[i].iph.source_ip[2],frame[i].iph.source_ip[3]);
            printf("%d.%d.%d.%d (TCP) ",frame[i].iph.dest_ip[0],frame[i].iph.dest_ip[1],frame[i].iph.dest_ip[2],frame[i].iph.dest_ip[3]);
            printf("sourceport = %d ",frame[i].tcph.source_port[0]*256+frame[i].tcph.source_port[1]);
            printf("destport = %d\n",frame[i].tcph.dest_port[0]*256+frame[i].tcph.dest_port[1]);
            }
        }
        else if(strcmp(frame[i].type, "icmp")==0){
            if(frame[i].broadcast==2){
                printf("%d.%d.%d.%d -> ",frame[i].iph.source_ip[0],frame[i].iph.source_ip[1],frame[i].iph.source_ip[2],frame[i].iph.source_ip[3]);
                printf("(broadcast)(ICMP) who is %d.%d.%d.%d, ",frame[i].iph.dest_ip[0],frame[i].iph.dest_ip[1],frame[i].iph.dest_ip[2],frame[i].iph.dest_ip[3]);
                if(frame[i].icmph.type==0){
                    printf("Echo Reply(type=0)\n");
                }
                else printf("\n");
            }
            
            
            else{
            printf("%d.%d.%d.%d -> ",frame[i].iph.source_ip[0],frame[i].iph.source_ip[1],frame[i].iph.source_ip[2],frame[i].iph.source_ip[3]);
            printf("%d.%d.%d.%d (ICMP), ",frame[i].iph.dest_ip[0],frame[i].iph.dest_ip[1],frame[i].iph.dest_ip[2],frame[i].iph.dest_ip[3]);
            if(frame[i].icmph.type==0){
                printf("Echo Reply (type=0)\n");
            }
            else if(frame[i].icmph.type==8)
                printf("Echo Request (type=8)\n");
               else printf("Unknow type (type=%d)\n",frame[i].icmph.type);
            }
        }
        
        
    }
    
}
/*********************************The Function of -V flag******************/
void V_flag(struct ethernet_frame *frame,int no){
    cout<<"\n";
    for(int i=0;i<no;i++){
        if(strcmp(frame[i].type, "other")==0){
            cout<<"ETHER:  ----- Ether Header -----\n";
            cout<<"ETHER:\n";
            cout<<"ETHER:  Packet "<<frame[i].pkt_id<<"\n";
            cout<<"ETHER:  Packet size = "<<frame[i].size <<" bytes\n";
            printf("ETHER:  Destination = %x:%x:%x:%x:%x:%x\n",frame[i].mach.dest_mac[0],frame[i].mach.dest_mac[1],frame[i].mach.dest_mac[2],frame[i].mach.dest_mac[3],frame[i].mach.dest_mac[4],frame[i].mach.dest_mac[5]);
            printf("ETHER:  Source      = %x:%x:%x:%x:%x:%x\n",frame[i].mach.source_mac[0],frame[i].mach.source_mac[1],frame[i].mach.source_mac[2],frame[i].mach.source_mac[3],frame[i].mach.source_mac[4],frame[i].mach.source_mac[5]);
            printf("ETHER:  Ethertype   = %02x%02x (unknown)\n",frame[i].mach.ethernet_type[0],frame[i].mach.ethernet_type[1]);
            cout<<"ETHER:\n";
        }
        
        
        
        if(strcmp(frame[i].type, "arp")==0){
            cout<<"ETHER:  ----- Ether Header -----\n";
            cout<<"ETHER:\n";
            cout<<"ETHER:  Packet "<< frame[i].pkt_id<<"\n";
            cout<<"ETHER:  Packet size = "<<frame[i].size <<" bytes\n";
            printf("ETHER:  Destination = %x:%x:%x:%x:%x:%x\n",frame[i].mach.dest_mac[0],frame[i].mach.dest_mac[1],frame[i].mach.dest_mac[2],frame[i].mach.dest_mac[3],frame[i].mach.dest_mac[4],frame[i].mach.dest_mac[5]);
            printf("ETHER:  Source      = %x:%x:%x:%x:%x:%x\n",frame[i].mach.source_mac[0],frame[i].mach.source_mac[1],frame[i].mach.source_mac[2],frame[i].mach.source_mac[3],frame[i].mach.source_mac[4],frame[i].mach.source_mac[5]);
            printf("ETHER:  Ethertype   = %02x%02x (ARP)\n",frame[i].mach.ethernet_type[0],frame[i].mach.ethernet_type[1]);
            cout<<"ETHER:\n";
            cout<<"ARP:  ----- ARP Frame -----\n";
            cout<<"ARP:  \n";
            cout<<"ARP:  Hardware type = 1 (Ethernet)\n";
            cout<<"ARP:  Protocol type = 0800 (IP)\n";
            printf("ARP:  Length of hardware address = %d bytes\n",frame[i].arph.length_ha);
            printf("ARP:  Length of protocol address = %d bytes\n",frame[i].arph.length_pa);
            if(frame[i].arph.op[0]*256+frame[i].arph.op[1]==1)
            printf("ARP:  Opcode %d (ARP Request)\n",frame[i].arph.op[0]*256+frame[i].arph.op[1]);
            else if (frame[i].arph.op[0]*256+frame[i].arph.op[1]==2)
            printf("ARP:  Opcode 2 (ARP Reply)\n");
            printf("ARP:  Sender's hardware address = %x:%x:%x:%x:%x:%x\n",frame[i].arph.source_ha[0],frame[i].arph.source_ha[1],frame[i].arph.source_ha[2],frame[i].arph.source_ha[3],frame[i].arph.source_ha[4],frame[i].arph.source_ha[5]);
            printf("ARP:  Sender's protocol address = %d.%d.%d.%d\n",frame[i].arph.source_ip[0],frame[i].arph.source_ip[1],frame[i].arph.source_ip[2],frame[i].arph.source_ip[3]);
            if(frame[i].broadcast==1||frame[i].arph.dest_ha[0]+frame[i].arph.dest_ha[1]+frame[i].arph.dest_ha[2]+frame[i].arph.dest_ha[3]+frame[i].arph.dest_ha[4]+frame[i].arph.dest_ha[5]==0)
             printf("ARP:  Target hardware address = ?\n");
            else
             printf("ARP:  Target hardware address = %x:%x:%x:%x:%x:%x\n",frame[i].arph.dest_ha[0],frame[i].arph.dest_ha[1],frame[i].arph.dest_ha[2],frame[i].arph.dest_ha[3],frame[i].arph.dest_ha[4],frame[i].arph.dest_ha[5]);
            printf("ARP:  Target protocol address = %d.%d.%d.%d\n",frame[i].arph.dest_ip[0],frame[i].arph.dest_ip[1],frame[i].arph.dest_ip[2],frame[i].arph.dest_ip[3]);
            cout<<"ARP:\n";
        }
        
        
        if(strcmp(frame[i].type, "icmp")==0){
            cout<<"ETHER:  ----- Ether Header -----\n";
            cout<<"ETHER:\n";
            cout<<"ETHER:  Packet "<< frame[i].pkt_id<<"\n";
            cout<<"ETHER:  Packet size = "<<frame[i].size <<" bytes\n";
            printf("ETHER:  Destination = %x:%x:%x:%x:%x:%x\n",frame[i].mach.dest_mac[0],frame[i].mach.dest_mac[1],frame[i].mach.dest_mac[2],frame[i].mach.dest_mac[3],frame[i].mach.dest_mac[4],frame[i].mach.dest_mac[5]);
            printf("ETHER:  Source      = %x:%x:%x:%x:%x:%x\n",frame[i].mach.source_mac[0],frame[i].mach.source_mac[1],frame[i].mach.source_mac[2],frame[i].mach.source_mac[3],frame[i].mach.source_mac[4],frame[i].mach.source_mac[5]);
            printf("ETHER:  Ethertype   = %02x%02x (IP)\n",frame[i].mach.ethernet_type[0],frame[i].mach.ethernet_type[1]);
            cout<<"ETHER:\n";
            cout<<"IP:  ----- IP Header -----\n";
            cout<<"IP:\n";
            printf("IP:  Version = %d\n",frame[i].iph.version);
            printf("IP:  Header length = %d bytes\n",frame[i].iph.size);
            printf("IP:  Type of service = %x\n",frame[i].iph.TOS);
            printf("IP:  Total length = %d bytes\n",frame[i].iph.length[0]*256+frame[i].iph.length[1]);
            printf("IP:  Identification = %d\n",frame[i].iph.ID[0]*256+frame[i].iph.ID[1]);
            cout<<"IP:  Flags\n";
            printf("IP:    .%d.. .... = ",frame[i].iph.flag1);
            if(frame[i].iph.flag1==1) printf("do not fragment\n"); else printf("allow fragment\n");
            printf("IP:    ..%d. .... = ",frame[i].iph.flag2);
            if(frame[i].iph.flag2==0) printf("last fragment\n"); else printf("no last fragment\n");
            printf("IP:  Fragment offset = %d bytes\n",frame[i].iph.offset);
            printf("IP:  Protocol = 1 (ICMP)\n");
            printf("IP:  Header checksum = %x%02x\n",frame[i].iph.header_checksum[0],frame[i].iph.header_checksum[1]);
            printf("IP:  Source address = %d.%d.%d.%d\n",frame[i].iph.source_ip[0],frame[i].iph.source_ip[1],frame[i].iph.source_ip[2],frame[i].iph.source_ip[3]);
            printf("IP:  Destination address = %d.%d.%d.%d\n",frame[i].iph.dest_ip[0],frame[i].iph.dest_ip[1],frame[i].iph.dest_ip[2],frame[i].iph.dest_ip[3]);
            
            if(frame[i].iph.size==20)
                printf("IP:  No options\n");
            else
                printf("IP:  Options Ignored\n");
            cout<<"IP:\n";
            cout<<"ICMP:  ----- ICMP Header -----\n";
            cout<<"ICMP: \n";
            if(frame[i].icmph.type==8)
            printf("ICMP: Type = 8 (Echo Request)\n");
            else if(frame[i].icmph.type==0)
                printf("ICMP: Type = 0 (Echo Reply)\n");
            else
                printf("ICMP: Type = %d(Unknown Type)\n",frame[i].icmph.type);
            printf("ICMP: Code = %d\n",frame[i].icmph.code);
            printf("ICMP: Checksum = %02x%02x\n",frame[i].icmph.checksum[0],frame[i].icmph.checksum[1]);
            printf("ICMP: Identifier = %d\n",frame[i].icmph.ID[0]*256+frame[i].icmph.ID[1]);
            printf("ICMP: Sequence number = %d\n",frame[i].icmph.sequence_number[0]*256+frame[i].icmph.sequence_number[1]);
            cout<<"ICMP:\n";
            
        }
        if(strcmp(frame[i].type, "udp")==0){
            cout<<"ETHER:  ----- Ether Header -----\n";
            cout<<"ETHER:\n";
            cout<<"ETHER:  Packet "<< frame[i].pkt_id<<"\n";
            cout<<"ETHER:  Packet size = "<<frame[i].size <<" bytes\n";
            printf("ETHER:  Destination = %x:%x:%x:%x:%x:%x\n",frame[i].mach.dest_mac[0],frame[i].mach.dest_mac[1],frame[i].mach.dest_mac[2],frame[i].mach.dest_mac[3],frame[i].mach.dest_mac[4],frame[i].mach.dest_mac[5]);
            printf("ETHER:  Source      = %x:%x:%x:%x:%x:%x\n",frame[i].mach.source_mac[0],frame[i].mach.source_mac[1],frame[i].mach.source_mac[2],frame[i].mach.source_mac[3],frame[i].mach.source_mac[4],frame[i].mach.source_mac[5]);
            printf("ETHER:  Ethertype   = %02x%02x (IP)\n",frame[i].mach.ethernet_type[0],frame[i].mach.ethernet_type[1]);
            cout<<"ETHER:\n";
            cout<<"IP:  ----- IP Header -----\n";
            cout<<"IP:\n";
            printf("IP:  Version = %d\n",frame[i].iph.version);
            printf("IP:  Header length = %d bytes\n",frame[i].iph.size);
            printf("IP:  Type of service = %x\n",frame[i].iph.TOS);
            printf("IP:  Total length = %d bytes\n",frame[i].iph.length[0]*256+frame[i].iph.length[1]);
            printf("IP:  Identification = %d\n",frame[i].iph.ID[0]*256+frame[i].iph.ID[1]);
            cout<<"IP:  Flags\n";
            printf("IP:    .%d.. .... = ",frame[i].iph.flag1);
            if(frame[i].iph.flag1==1) printf("do not fragment\n"); else printf("allow fragment\n");
            printf("IP:    ..%d. .... = ",frame[i].iph.flag2);
            if(frame[i].iph.flag2==0) printf("last fragment\n"); else printf("no last fragment\n");
            printf("IP:  Fragment offset = %d bytes\n",frame[i].iph.offset);
            printf("IP:  Protocol = 17 (UDP)\n");
            printf("IP:  Header checksum = %x%02x\n",frame[i].iph.header_checksum[0],frame[i].iph.header_checksum[1]);
            printf("IP:  Source address = %d.%d.%d.%d\n",frame[i].iph.source_ip[0],frame[i].iph.source_ip[1],frame[i].iph.source_ip[2],frame[i].iph.source_ip[3]);
            printf("IP:  Destination address = %d.%d.%d.%d\n",frame[i].iph.dest_ip[0],frame[i].iph.dest_ip[1],frame[i].iph.dest_ip[2],frame[i].iph.dest_ip[3]);
            
            if(frame[i].iph.size==20)
                printf("IP:  No options\n");
            else
                printf("IP:  Options Ignored\n");
            cout<<"IP:\n";
            cout<<"UDP:  ----- UDP Header -----\n";
            cout<<"UDP: \n";
            printf("UDP:  Source port = %d\n",frame[i].udph.source_port[0]*256+frame[i].udph.source_port[1]);
            printf("UDP:  Destination port = %d\n",frame[i].udph.dest_port[0]*256+frame[i].udph.dest_port[1]);
            printf("UDP:  Message length = %d\n",frame[i].udph.length[0]*256+frame[i].udph.length[1]);
            printf("UDP:  Checksum = %x\n",frame[i].udph.checksome[0]*256+frame[i].udph.checksome[1]);
            cout<<"UDP:\n";
            
        }
        if(strcmp(frame[i].type, "tcp")==0){
            cout<<"ETHER:  ----- Ether Header -----\n";
            cout<<"ETHER:\n";
            cout<<"ETHER:  Packet "<< frame[i].pkt_id<<"\n";
            cout<<"ETHER:  Packet size = "<<frame[i].size <<" bytes\n";
            printf("ETHER:  Destination = %x:%x:%x:%x:%x:%x\n",frame[i].mach.dest_mac[0],frame[i].mach.dest_mac[1],frame[i].mach.dest_mac[2],frame[i].mach.dest_mac[3],frame[i].mach.dest_mac[4],frame[i].mach.dest_mac[5]);
            printf("ETHER:  Source      = %x:%x:%x:%x:%x:%x\n",frame[i].mach.source_mac[0],frame[i].mach.source_mac[1],frame[i].mach.source_mac[2],frame[i].mach.source_mac[3],frame[i].mach.source_mac[4],frame[i].mach.source_mac[5]);
            printf("ETHER:  Ethertype   = %02x%02x (IP)\n",frame[i].mach.ethernet_type[0],frame[i].mach.ethernet_type[1]);
            cout<<"ETHER:\n";
            cout<<"IP:  ----- IP Header -----\n";
            cout<<"IP:\n";
            printf("IP:  Version = %d\n",frame[i].iph.version);
            printf("IP:  Header length = %d bytes\n",frame[i].iph.size);
            printf("IP:  Type of service = %x\n",frame[i].iph.TOS);
            printf("IP:  Total length = %d bytes\n",frame[i].iph.length[0]*256+frame[i].iph.length[1]);
            printf("IP:  Identification = %d\n",frame[i].iph.ID[0]*256+frame[i].iph.ID[1]);
            cout<<"IP:  Flags\n";
            printf("IP:    .%d.. .... = ",frame[i].iph.flag1);
            if(frame[i].iph.flag1==1) printf("do not fragment\n"); else printf("allow fragment\n");
            printf("IP:    ..%d. .... = ",frame[i].iph.flag2);
            if(frame[i].iph.flag2==0) printf("last fragment\n"); else printf("no last fragment\n");
            printf("IP:  Fragment offset = %d bytes\n",frame[i].iph.offset);
            printf("IP:  Protocol = 6 (TCP)\n");
            printf("IP:  Header checksum = %x%02x\n",frame[i].iph.header_checksum[0],frame[i].iph.header_checksum[1]);
            printf("IP:  Source address = %d.%d.%d.%d\n",frame[i].iph.source_ip[0],frame[i].iph.source_ip[1],frame[i].iph.source_ip[2],frame[i].iph.source_ip[3]);
            printf("IP:  Destination address = %d.%d.%d.%d\n",frame[i].iph.dest_ip[0],frame[i].iph.dest_ip[1],frame[i].iph.dest_ip[2],frame[i].iph.dest_ip[3]);
          
            if(frame[i].iph.size==20)
                printf("IP:  No options\n");
            else
                printf("IP:  Options Ignored\n");
            cout<<"IP:\n";
            cout<<"TCP:  ----- TCP Header -----\n";
            cout<<"TCP: \n";
            printf("TCP:  Source port = %d\n",frame[i].tcph.source_port[0]*256+frame[i].tcph.source_port[1]);
            printf("TCP:  Destination port = %d\n",frame[i].tcph.dest_port[0]*256+frame[i].tcph.dest_port[1]);
            
            
            printf("TCP:  Sequence number = %ld\n",frame[i].tcph.sequence_number[0]*(int)pow(256,3)+frame[i].tcph.sequence_number[1]*(int)pow(256,2)+frame[i].tcph.sequence_number[2]*256+frame[i].tcph.sequence_number[3]);
            
            printf("TCP:  Acknowledgement number = %ld\n",frame[i].tcph.ack_number[0]*(int)pow(256,3)+frame[i].tcph.ack_number[1]*(int)pow(256,2)+frame[i].tcph.ack_number[2]*256+frame[i].tcph.ack_number[3]);
            
            
            
            printf("TCP:  Data offset = %d bytes\n",4*frame[i].tcph.data_offset);
            cout<<"TCP:  Flags\n";
            printf("TCP:      ..%d. .... = ",frame[i].tcph.UGR);
            if(frame[i].tcph.UGR==1) printf("Urgent pointer\n"); else printf("No urgent pointer\n");
            printf("TCP:      ...%d .... = ",frame[i].tcph.ACK);
            if(frame[i].tcph.ACK==1) printf("Acknowledgement\n"); else printf("No acknowledgement\n");
            printf("TCP:      .... %d... = ",frame[i].tcph.PSH);
            if(frame[i].tcph.PSH==1) printf("Push\n"); else printf("No push\n");
            printf("TCP:      .... .%d.. = ",frame[i].tcph.RST);
            if(frame[i].tcph.RST==1) printf("Reset\n"); else printf("No reset\n");
            printf("TCP:      .... ..%d. = ",frame[i].tcph.SYN);
            if(frame[i].tcph.SYN==1) printf("Syn\n"); else printf("No Syn\n");
            printf("TCP:      .... ...%d = ",frame[i].tcph.FIN);
            if(frame[i].tcph.FIN==1) printf("Fin\n"); else printf("No Fin\n");
            printf("TCP:  Window = %d\n",frame[i].tcph.window[0]*256+frame[i].tcph.window[1]);
            printf("TCP:  Checksum = %x\n",frame[i].tcph.checksum[0]*256+frame[i].tcph.checksum[1]);
            //printf("TCP:  Checksum = %x%02x\n",frame[i].tcph.checksum[0],frame[i].tcph.checksum[1]);
            printf("TCP:  Urgent pointer = %d\n",frame[i].tcph.urgent_pointer[0]*256+frame[i].tcph.urgent_pointer[1]);
            if(frame[i].tcph.data_offset*4==20)
            cout<<"TCP:  No options\n";
            else
            cout<<"TCP:  Options ignored\n";
            cout<<"TCP:\n";
            
        }
        if(i<no-1){
        cout<<"\n";
        }
        
        
        
        
    }
}



int main(int argc, char *argv[]) {
    std::string file_name;
    if(argc == 2){
        std::string name(argv[1]);
        file_name = name;
    }else if(argc == 3){
        std::string name(argv[2]);
        file_name = name;
    }else if(argc == 4){
        std::string name(argv[3]);
        file_name = name;
    }
    else{
       printf("Wrong Command!\n");
    }
    
    FILE *fp = fopen(file_name.c_str(), "rb");
    if( fp == NULL)
        printf("Error at opening files!\n");
    /********************Get file Size**********************/
    fseek(fp,0,SEEK_END);
    int file_size=(int)ftell(fp);
    
    struct ethernet_frame *frame_out;
    frame_out =(struct ethernet_frame *)malloc(sizeof(struct ethernet_frame)*10000);
    int no_frame=0;
    int temp_file_size=0;
    uint32_t frame_size;
    fseek(fp,0,SEEK_SET);
    while(temp_file_size<file_size){
        fread(&frame_size,4,1,fp);
        frame_out[no_frame].size=ntohl(frame_size);
        temp_file_size=4+frame_out[no_frame].size+temp_file_size;
        for(int i=0;i<frame_out[no_frame].size;i++){
            fread(&frame_out[no_frame].frame_data[i],1,1,fp);
        }
        frame_out[no_frame].pkt_id=no_frame;
        no_frame++;
    }
    get_ethernet_header(frame_out, no_frame);
    get_ip_header(frame_out, no_frame);
    get_arp_header(frame_out, no_frame);
    get_udp_header(frame_out, no_frame);
    get_tcp_header(frame_out, no_frame);
    get_icmp_header(frame_out, no_frame);
    if(argc==2){
        no_flag(frame_out,no_frame);
    }
    else if(argc==3){
            std::string method(argv[1]);
    if(method == "-v"){
        v_flag(frame_out,no_frame);
    }else if(method == "-V"){
        V_flag(frame_out, no_frame);
    }else{
        std::cout << "Wrong Flag\n" << std::endl;
       }
    }
    else if(argc==4){
        int no=atoi(argv[2]);
        no_flag(frame_out,no);
    }
    else
    std::cout << "Error, Input agin\n" << std::endl;
    free(frame_out);
    return 0;
}
