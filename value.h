#ifndef VALUE_H
#define VALUE_H
#include <stdint.h>
#include <iostream>
typedef struct value_beacon
{
    uint current_channel;
    uint8_t ESSID[32]{0};
    uint beacon_cnt;
    uint Data_cnt{0};
}__attribute__((packed))vbea;






#endif // VALUE_H
