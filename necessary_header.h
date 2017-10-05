#ifndef NECESSARY_HEADER_H
#define NECESSARY_HEADER_H
#ifndef RADIO_H
#define RADIO_H
#include <stdint.h>

struct radiotap_header
{
    uint8_t header_version;
    uint8_t header_pad;
    uint16_t header_len;


//Present flags
    uint32_t TSFT:1;
    uint32_t Flags:1;
    uint32_t Rate:1;
    uint32_t Channel:1;
    uint32_t FHSS:1;
    uint32_t dBm_Ant_Siganl:1;
    uint32_t dBm_Ant_Noise:1;
    uint32_t Lock_Quality:1;
    uint32_t TX_Attenuation:1;
    uint32_t dB_TX_Attenuation:1;
    uint32_t dBm_TX_Power:1;
    uint32_t Antenna_flag:1;
    uint32_t dB_Ant_Signal:1;
    uint32_t db_Ant_Noise:1;
    uint32_t RXflags:1;
    uint32_t P_flags_padding:3;
    uint32_t Channel_plus:1;
    uint32_t MCS_info:1;
    uint32_t A_MPDU_Status:1;
    uint32_t VHT_info:1;
    uint32_t Reserved:7;
    uint32_t Radio_NS:1;
    uint32_t Vendor_NS:1;
    uint32_t Ext:1;
//######################################################


    uint64_t MAC_timestamp;


//flags
    uint8_t CFP:1;
    uint8_t Preamble:1;
    uint8_t WEP:1;
    uint8_t Fragementation:1;
    uint8_t FCS:1;
    uint8_t Data_pad:1;
    uint8_t Bad_FCS:1;
    uint8_t Short_GI:1;
//######################################################


    uint8_t Date_Rate;
    uint16_t Channel_freq;


//Channel_flags;
    uint16_t Ch_padding:4;
    uint16_t Turbo:1;
    uint16_t Complementary_code_keying:1;
    uint16_t Orthogonal_Freq:1;
    uint16_t GHz_2:1;
    uint16_t GHz_5:1;
    uint16_t Passive:1;
    uint16_t Dynamic_CCK:1;
    uint16_t Gaussian_freq:1;
    uint16_t GSM:1;
    uint16_t Static_Turbo:1;
    uint16_t Half_Rate_Channel:1;
    uint16_t Quarter_Rate_Channel:1;
//######################################################

    uint8_t SSI_Signal;
    uint8_t Antenna;
    uint16_t RX_flags;
};

struct ieee80211_common
{
    //Frame Control Field
    uint8_t version:2;
    uint8_t Type:2;
    uint8_t Sutype:4;
    //flags
    uint8_t Ds:2;
    uint8_t more:1;
    uint8_t retry:1;
    uint8_t pwr:1;
    uint8_t more2:1;
    uint8_t protect:1;
    uint8_t order:1;

    uint16_t Duration;
};
struct ieee80211_Null_function
{
    struct ieee80211_common c;
    uint8_t BSSID[6];
    uint8_t STA[6];
    uint8_t Dst_addr[6];

    uint16_t Fragment_num:4;
    uint16_t Sequence_num:12;

    uint32_t Frame_check_seq;
};

struct ieee80211_Probe_Request //beacon frame 와 Probe response랑 구조가 같음 나중에 완성하고 따로둘 필요없으면 합치자
{
    struct ieee80211_common c;
    uint8_t Dst_addr[6];
    uint8_t Src_addr[6];
    uint8_t BSSID[6];

    uint16_t Fragment_num:4;
    uint16_t Sequence_num:12;
};

struct ieee80211_Probe_Response
{
    struct ieee80211_common c;
    uint8_t Dst_addr[6];
    uint8_t Src_addr[6];
    uint8_t BSSID[6];

    uint16_t Fragment_num:4;
    uint16_t Sequence_num:12;
};

struct ieee80211_Beacon_frame
{
    struct ieee80211_common c;
    uint8_t Receiver_addr[6];
    uint8_t Trasmitter_addr[6];
    uint8_t BSSID[6];

    uint16_t Fragment_num:4;
    uint16_t Sequence_num:12;
};
struct ieee80211_Qos_Data41
{
    struct ieee80211_common c;
    uint8_t BSSID[6];
    uint8_t STA[6];
    uint8_t Dst_addr[6];

    uint16_t Fragment_num:4;
    uint16_t Sequence_num:12;

    uint16_t Qos_Control;
    uint16_t CCMP_para;
};
struct ieee80211_Qos_Data42
{
    struct ieee80211_common c;
    uint8_t STA[6];
    uint8_t BSSID[6];
    uint8_t Dst_addr[6];

    uint16_t Fragment_num:4;
    uint16_t Sequence_num:12;

    uint16_t Qos_Control;
    uint16_t CCMP_para;
};
struct ieee80211_Block_Ack
{
    struct ieee80211_common c;

    uint16_t Fragment_num:4;
    uint16_t Sequence_num:12;

    uint8_t Receiver_addr[6];
    uint8_t Trasmitter_addr[6];
    uint16_t Block_Ack_Requeset_control;
    uint16_t Block_Ack_Starting_Seq_control;
    uint64_t Block_Ack_Bitmap;
    uint32_t Frame_check_seq;
};
struct ieee80211_Block_Ack_req
{
    struct ieee80211_common c;
    uint8_t Receiver_addr[6];
    uint8_t Trasmitter_addr[6];
    uint16_t Block_Ack_Requeset_control;
    uint16_t Block_Ack_Starting_Seq_control;
};

struct ieee80211_Clear_to_send
{
    struct ieee80211_common c;
    uint8_t Receiver_addr[6];
};

struct ieee80211_Reqeust_to_send
{
    struct ieee80211_common c;
    uint8_t Receiver_addr[6];
    uint8_t Trasmitter_addr[6];
    uint32_t Frame_check_seq;
};

struct ieee80211_Acknowledgement
{
    struct ieee80211_common c;
    uint8_t Receiver_addr[6];
    uint32_t Frame_check_seq;
};

struct ieee80211_Data
{
    struct ieee80211_common c;
    uint8_t STA[6];
    uint8_t BSSID[6];
    uint8_t Src_addr[6];

    uint16_t Fragment_num:4;
    uint16_t Sequence_num:12;

    uint16_t CCMP_para;
};

struct ieee80211_Deauthentication
{
    struct ieee80211_common c;
    uint8_t Receiver_addr[6];
    uint8_t Trasmitter_addr[6];
    uint8_t BSSID[6];

    uint16_t Fragment_num:4;
    uint16_t Sequence_num:12;
};

struct ieee80211_Association
{
    struct ieee80211_common c;
    uint8_t Dst_addr[6];
    uint8_t Src_addr[6];
    uint8_t BSSID[6];

    uint16_t Fragment_num:4;
    uint16_t Sequence_num:12;
};

struct ieee80211_Ressociation
{
    struct ieee80211_common c;
    uint8_t Dst_addr[6];
    uint8_t Src_addr[6];
    uint8_t BSSID[6];

    uint16_t Fragment_num:4;
    uint16_t Sequence_num:12;
};


//################################## Wireless LAN_Mangement frame##################################
struct ieee80211_wireless_LAN_mg_Beacon
{
//Fixed Para
    uint64_t Timestamp;
    uint16_t Beacon_interval;
    //Capabilities_info
    uint16_t ESS:1;
    uint16_t IBSS:1;
    uint16_t CFP:2;
    uint16_t Privacy:1;
    uint16_t Short_Preamble:1;
    uint16_t PBCC:1;
    uint16_t Channel_Agility:1;
    uint16_t Spectrum_Management:1;
    uint16_t CFP2:1;
    uint16_t Short_Slot_Time:1;
    uint16_t Automatic_power:1;
    uint16_t Radio_Measurement:1;
    uint16_t DSSS_PFDM:1;
    uint16_t Delayed_Block_Ack:1;
    uint16_t Immediate_Block_Ack:1;
}__attribute__((__packed__));

struct ieee80211_wireless_LAN_mg_Association
{
    //Capabilities_info
    uint16_t ESS:1;
    uint16_t IBSS:1;
    uint16_t CFP:2;
    uint16_t Privacy:1;
    uint16_t Short_Preamble:1;
    uint16_t PBCC:1;
    uint16_t Channel_Agility:1;
    uint16_t Spectrum_Management:1;
    uint16_t CFP2:1;
    uint16_t Short_Slot_Time:1;
    uint16_t Automatic_power:1;
    uint16_t Radio_Measurement:1;
    uint16_t DSSS_PFDM:1;
    uint16_t Delayed_Block_Ack:1;
    uint16_t Immediate_Block_Ack:1;

    uint16_t Status_code;
};

struct ieee80211_wireless_LAN_mg_Reassociation
{
    //Capabilities_info
    uint16_t ESS:1;
    uint16_t IBSS:1;
    uint16_t CFP:2;
    uint16_t Privacy:1;
    uint16_t Short_Preamble:1;
    uint16_t PBCC:1;
    uint16_t Channel_Agility:1;
    uint16_t Spectrum_Management:1;
    uint16_t CFP2:1;
    uint16_t Short_Slot_Time:1;
    uint16_t Automatic_power:1;
    uint16_t Radio_Measurement:1;
    uint16_t DSSS_PFDM:1;
    uint16_t Delayed_Block_Ack:1;
    uint16_t Immediate_Block_Ack:1;

    uint16_t Listen_Interval;
    uint8_t CurrentAP[6];
};

struct ieee80211_wireless_LAN_mg_Deauthentication
{
    uint16_t Reason_code;
};

// ################################# Tag Parameters #################################
struct Tagpara_common
{
    uint8_t TagNum;
    uint8_t TagLen;
};
struct Tagpara_Supported_Rates
{
    struct Tagpara_common Tc;
    uint8_t Supported_rate1;
    uint8_t Supported_rate2;
    uint8_t Supported_rate3;
    uint8_t Supported_rate4;
    uint8_t Supported_rate5;
    uint8_t Supported_rate6;
    uint8_t Supported_rate7;
    uint8_t Supported_rate8;
};

struct Tagpara_Extended_Supported_Rates
{
    struct Tagpara_common Tc;
    uint8_t Extended_Supported_Rate1;
    uint8_t Extended_Supported_Rate2;
    uint8_t Extended_Supported_Rate3;
    uint8_t Extended_Supported_Rate4;
};

struct Tagpara_DS_para_set
{
     struct Tagpara_common Tc;
     uint8_t Current_Channel;
};

struct RSN_info
{
    uint8_t RSN_ver;
    //AES는 보류
};

struct HT_Capabilities
{
     struct Tagpara_common Tc;
     //HT Capabilites info
     uint16_t HT_LDPC:1;
     uint16_t HT_Support:1;
     uint16_t SM_Power:2;
     uint16_t HT_Green:1;
     uint16_t HT_Short_GI20:1;
     uint16_t HT_Short_GI40:1;
     uint16_t HT_Tx_STBC:1;
     uint16_t HT_Rx_STBC:2;
     uint16_t HT_Delayed_Block_ACK:1;
     uint16_t HT_Max_A_MSDU:1;
     uint16_t HT_DSSS_CCK_mode:1;
     uint16_t HT_PSMP:1;
     uint16_t HT_Forty:1;
     uint16_t HT_L_SIG:1;
     //A-MPDU
     uint8_t Maximum_Rx_A_MPDU_len:2;
     uint8_t MPDU_Density:3;
     uint8_t Reserved:3;
     //나머지는 필요 없는것 같음
};
//####################################################################################



#endif // RADIO_H

#endif // NECESSARY_HEADER_H
