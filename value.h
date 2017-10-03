#ifndef VALUE_H
#define VALUE_H
#include <stdint.h>
#include <iostream>
typedef struct value_beacon
{
    uint current_channel;
    uint8_t ESSID[32]{0};
    uint beacon_cnt{0};
    uint Data_cnt{0};
}__attribute__((packed))vbea;


typedef struct STA_KEY
{
   u_int8_t STA[6];
}__attribute__((packed))STA_key;


typedef struct STA_VALUE
{
    uint8_t bssid[6];
    uint frames_cnt;
    uint8_t PROBE_name[32]{0};
}__attribute__((packed))STA_value;


#endif // VALUE_H
