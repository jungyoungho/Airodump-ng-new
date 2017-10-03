#ifndef STA_KEY_H
#define STA_KEY_H
#include <map>

using namespace std;

class sta_key
{
 public:
    uint8_t STA[6];

    bool operator < (const sta_key sta_key_make) const{
        return tie(STA[0],STA[1],STA[2],STA[3],STA[4],STA[5]) < tie(sta_key_make.STA[0],sta_key_make.STA[1],sta_key_make.STA[2],sta_key_make.STA[3],sta_key_make.STA[4],sta_key_make.STA[5]);
    }
    sta_key();
}__attribute__((packed));
#endif // STA_KEY_H
