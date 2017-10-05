#ifndef STA_VALUE_H
#define STA_VALUE_H
#include <map>

using namespace std;

class sta_value
{
 public:
    uint8_t bssid[6];
    uint frames_cnt{0};
    uint8_t PROBE_name[32]{0};
    bool operator < (const sta_value sta_value_make) const{
        return tie(bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]) < tie(sta_value_make.bssid[0],sta_value_make.bssid[1],sta_value_make.bssid[2],sta_value_make.bssid[3],sta_value_make.bssid[4],sta_value_make.bssid[5]);
    }
    sta_value();
}__attribute__((packed));

#endif // STA_VALUE_H

