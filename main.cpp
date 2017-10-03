#include <iostream>
#include <string.h>
#include <pcap.h>
#include <map>
#include <unistd.h>
#include "key.h"
#include "sta_key.h"
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
        struct sta_key ks;
        struct value_beacon v,pv,pqv;
        struct STA_VALUE sv,nv;
        //######beacon map#######
        map <key,vbea> mapbea;
        map <key,vbea>::iterator bea_it;

        key bssid_key;
        vbea value_bea;
        //######station map#######
        map <sta_key,SV> mapsta;
        map <sta_key,SV> ::iterator sta_it;

        sta_key key_sta;    //NULL & QOS DATA
        SV value_sta; // NULL & QOS DATA BSSID, FRAME CNT, PROBE ESSID


        value_bea.current_channel=0;
        while((res=pcap_next_ex(pcd, &pkthdr, &packet))>=0)
        {
            int ESSID_LEN=0,pv_LEN=0,pqv_LEN=0;

            if(res==1)
            {
                int packet_len = pkthdr->len;
                struct radiotap_header *radio_h = (struct radiotap_header*)packet;
                packet += radio_h->header_len;
                struct ieee80211_common *common = (struct ieee80211_common *)packet;
                memset(value_bea.ESSID,0,32);
                memset(value_sta.PROBE_name,0,32);
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
                                mapbea.insert(pair<key,vbea>(bssid_key,value_bea)); //이 부분 띵킹좀 왜냐하면 ff ff 00 00 0 00 이나옴 error
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
                        case 4: // probe request -> QOS's STA is key!!
                        {
                            //struct ieee80211_Probe_Request *Probe_Req = (struct ieee80211_Probe_Request*)packet;
                            packet += sizeof(struct ieee80211_Probe_Request);
                            int a{0};
                            while(packet_len>0)
                            {
                                if(a==1)
                                    break;
                                struct Tagpara_common *T_common = (struct Tagpara_common *)packet;
                                if(T_common->TagLen==0) //SSID가 없을 때가 있음
                                    break;
                                switch (T_common->TagNum)
                                {
                                    case 0:
                                    {
                                        if(a==1)
                                            break;
                                        packet += sizeof(struct Tagpara_common);
                                        pqv_LEN =T_common->TagLen;
                                        memcpy(pqv.ESSID,packet,T_common->TagLen);
                                        if(packet_len < T_common->TagLen)
                                            break;
                                        else if(T_common->TagLen!=0)
                                        {
                                           packet += T_common->TagLen;
                                           packet_len -= T_common->TagLen;
                                        }
                                        a=1;//check point
                                    }
                                    break;
                                    default:
                                    {
                                         packet += sizeof(struct Tagpara_common);
                                         packet += T_common->TagLen;
                                         packet_len -=T_common->TagLen;
                                    }
                                    break;
                                }
                            }
                        }
                        break;
                        case 5:  //probe response -> QOS's STA is key!!
                        {
                            //struct ieee80211_Probe_Response *Probe_Res = (struct ieee80211_Probe_Response *)packet;
                            packet += sizeof(struct ieee80211_Probe_Response) + sizeof(struct ieee80211_wireless_LAN_mg_Beacon);
                            int a{0};
                            while(packet_len>0)
                            {
                                if(a==1)
                                    break;
                                struct Tagpara_common *T_common = (struct Tagpara_common *)packet;
                                switch (T_common->TagNum)
                                {
                                    case 0:
                                    {
                                        if(a==1)
                                            break;
                                        pv_LEN=T_common->TagLen;
                                        packet +=sizeof(struct Tagpara_common);
                                        memcpy(pv.ESSID,packet,T_common->TagLen);
                                        if(packet_len < T_common->TagLen)
                                            break;
                                        else if(T_common->TagLen!=0)
                                        {
                                           packet += T_common->TagLen;
                                           packet_len -= T_common->TagLen;
                                        }
                                        a=1;//check point
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
                    }
                 }
                else if(common->Type==2)
                {
                    switch (common->Sutype)
                    {
                        case 0: //DATA
                        {
                                if((bea_it = mapbea.find(bssid_key))!=mapbea.end())
                                {
                                      bea_it->second.Data_cnt+= 1;
                                }
                                else
                                {
                                    value_bea.Data_cnt = 0;
                                    mapbea.insert(pair<key,vbea>(bssid_key,value_bea));
                                }
                                //얘는 갯수만 필요!! Beacon value
                        }
                        break;
                        case 4: //NULL FUCNTION
                        {
                            struct ieee80211_Null_function *N_func = (struct ieee80211_Null_function *)packet;
                            memcpy(ks.STA,N_func->STA,6);
                            memcpy(value_sta.bssid,N_func->BSSID,6); //sv use??
                        }
                        break;
                        case 8: //QOS DATA
                        {
                            if((bea_it = mapbea.find(bssid_key))!=mapbea.end())
                            {
                                  bea_it->second.Data_cnt+= 1;
                            }
                            else
                            {
                                value_bea.Data_cnt = 0;
                                mapbea.insert(pair<key,vbea>(bssid_key,value_bea));
                            }
                            struct ieee80211_Qos_Data *QData = (struct ieee80211_Qos_Data *)packet;
                            memcpy(ks.STA,QData->STA,6);
                            memcpy(value_sta.bssid,QData->BSSID,6);  //sv use??
                        }
                        break;
                    }
                }
                 //################## BEACON ###################
                 memcpy(bssid_key.save_bssid,k.save_bssid,6);
                 value_bea.current_channel=v.current_channel;
                 memcpy(value_bea.ESSID,v.ESSID,ESSID_LEN);
                 //###################### map ######################
                 mapbea.insert(pair<key,vbea>(bssid_key,value_bea));
                 system("clear");

                 cout << "BSSID                   Beacons   #Data      CH      ESSID\n"<<endl;
                 for(bea_it = mapbea.begin(); bea_it!=mapbea.end(); advance(bea_it,1))
                 {
                     for(int i=0; i<6; i++)
                        printf("%02X ",bea_it->first.save_bssid[i]);
                     cout <<"\t" << bea_it->second.beacon_cnt;
                     cout <<"\t  " << bea_it->second.Data_cnt;
                     cout <<"\t     " << bea_it->second.current_channel;
                     cout <<"\t     "<< bea_it->second.ESSID<< endl;
                 }
                 printf("\n\n");

                 //################## QOS DATA ################### //start here go map but thinking!!
                 memcpy(key_sta.STA,ks.STA,6);
                 //memcpy(value_sta.PROBE_name,pv.ESSID,pv_LEN); //probe res essid value save  probe와 어떻게 매칭시킬것인지 생각해보기
                 //memcpy(value_sta.PROBE_name,pqv.ESSID,pqv_LEN); //probe req essid value save  probe와 어떻게 매칭시킬것인지 생각해보기
                 mapsta.insert(pair<sta_key,SV>(key_sta,value_sta));

/*
                 for(sta_it = mapsta.begin(); sta_it!=mapsta.end(); advance(sta_it,1))
                 {
                     for(int i=0; i<6; i++)
                         printf("%02X ",sta_it->first.STA[i]); //key 에 sta값 들어간건 성공했는데 value bssid도 이런식으로 만들어줘야할듯
                     cout << endl;

                 }
                 */

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
