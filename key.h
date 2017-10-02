#ifndef KEY_H
#define KEY_H
#include <map>

using namespace std;

class key
{
 public:
    uint8_t save_bssid[6];

    bool operator < (const key key_make) const{
        return tie(save_bssid[0],save_bssid[1],save_bssid[2],save_bssid[3],save_bssid[4],save_bssid[5]) < tie(key_make.save_bssid[0],key_make.save_bssid[1],key_make.save_bssid[2],key_make.save_bssid[3],key_make.save_bssid[4],key_make.save_bssid[5]);
    }
    key();
}__attribute__((packed));
#endif // KEY_H
