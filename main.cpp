#include <iostream>
#include <string.h>
#include <pcap.h>
#include <map>
#include <unistd.h>
#include "key.h"
#include "necessary_header.h"
#include "value.h"

using namespace std;

int main(int argc, char *argv[])
{
    if(argc!=2)
        {
            cout << "******* 인자값이 잘못되었거나 인자값이 존재하지 않습니다 *******" << endl;;
            cout << " 사용법 : interface name " << endl;
        }
        char *interface = argv[1];
        cout << " >> Interface name = "<< interface << endl;


        char errbuf[PCAP_ERRBUF_SIZE];

        pcap_t *pcd;
        pcd = pcap_open_live(interface, 2048, 1 , 2000, errbuf);
        if (pcd == NULL)
        {
            printf("%s\n", errbuf);
            return 0;
        }

        struct pcap_pkthdr *pkthdr;
        const u_char *packet;
        int res;
        struct key k;
        struct value_beacon v;

        map <key,vbea> mapbea;
        map <key,vbea>::iterator bea_it;
        key bssid_key;
        vbea value_bea;
        value_bea.current_channel=0;
        while((res=pcap_next_ex(pcd, &pkthdr, &packet))>=0)
        {
            int ESSID_LEN=0;
            if(res==1)
            {
                int packet_len = pkthdr->len;
                struct radiotap_header *radio_h = (struct radiotap_header*)packet;
                packet += radio_h->header_len;
                struct ieee80211_common *common = (struct ieee80211_common *)packet;
                memset(value_bea.ESSID,0,32);
                if(common->Type == 0)
                {
                    switch(common->Sutype)
                    {
                        case 8:
                        {
                            if((bea_it = mapbea.find(bssid_key))!=mapbea.end())
                            {
                                  bea_it->second.beacon_cnt += 1;
                            }
                            else
                            {
                                value_bea.beacon_cnt = 0;
                                mapbea.insert(pair<key,vbea>(bssid_key,value_bea)); //이부분 띵킹좀 왜냐하면 ff ff 00 00 0 00 이나옴
                            }
                            //cout <<"Beacon Frame" <<endl;
                            struct ieee80211_Beacon_frame *Beacon_f = (struct ieee80211_Beacon_frame *)packet;
                            memcpy(k.save_bssid,Beacon_f->BSSID,6);
                            packet += sizeof(struct ieee80211_Beacon_frame) + sizeof(struct ieee80211_wireless_LAN_mg_Beacon);

                            int a{0},b{0};
                            while(packet_len>0)
                            {

                                if(a==1 && b==1)
                                    break;
                                struct Tagpara_common *T_common = (struct Tagpara_common *)packet;

                                switch (T_common->TagNum)
                                {
                                    case 0:
                                    {
                                        if(a==1)
                                            break;
                                        packet += sizeof(struct Tagpara_common);
                                        ESSID_LEN=T_common->TagLen;
                                        memcpy(v.ESSID, packet,T_common->TagLen);
                                        if(packet_len < T_common->TagLen)
                                            break;
                                        else if(T_common->TagLen!=0)
                                        {
                                            packet += T_common->TagLen;
                                            packet_len -=T_common->TagLen;
                                        }
                                        a=1;
                                    }
                                    break;

                                    case 3:
                                    {
                                        if(b==1)
                                            break;
                                        struct Tagpara_DS_para_set *DS = (struct Tagpara_DS_para_set *)packet;
                                        v.current_channel=DS->Current_Channel;
                                        //cout << "CHANNEL = " <<v.current_channel<<endl;
                                        packet += sizeof(struct Tagpara_common);
                                        if(packet_len < T_common->TagLen)
                                            break;
                                        else if(T_common->TagLen!=0)
                                        {
                                            packet += T_common->TagLen;
                                            packet_len -=T_common->TagLen;
                                        }
                                        b=1;
                                    }
                                    break;

                                    default:
                                    {
                                        packet += sizeof(struct Tagpara_common);
                                        if(packet_len < T_common->TagLen)
                                            break;
                                        else if(T_common->TagLen!=0)
                                        {
                                            packet += T_common->TagLen;
                                            packet_len -= T_common->TagLen;
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                        break;
                        case 5:
                        {

                        }
                        break;
                    }
                 }
                 memcpy(bssid_key.save_bssid,k.save_bssid,6);
                 value_bea.current_channel=v.current_channel;
                 memcpy(value_bea.ESSID,v.ESSID,ESSID_LEN);

//###################### map ######################
                 mapbea.insert(pair<key,vbea>(bssid_key,value_bea));
                 system("clear");
                 cout << "BSSID                   Beacons         CH      ESSID\n"<<endl;
                 for(bea_it = mapbea.begin(); bea_it!=mapbea.end(); advance(bea_it,1))
                 {
                     for(int i=0; i<6; i++)
                        printf("%02X ",bea_it->first.save_bssid[i]);
                     cout <<"\t" << bea_it->second.beacon_cnt;
                     cout <<"\t\t" <<bea_it->second.current_channel;
                     cout <<"\t"<< bea_it->second.ESSID<<endl;
                 }
                 printf("\n\n");
            }
            else if(res==0)
            {
                printf(">> Time out Error\n");
                continue;
            }
            else if(res==-1)
            {
                printf(">> Error!!\n");
            }
            else if(res==-2)
            {
                printf("EOF");
            }
            else
                break;
        }


        pcap_close(pcd);
        return 0;
}
