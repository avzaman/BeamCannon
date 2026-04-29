#include <pcap.h>
#include <cstdio>
#include <cstring>
#include <vector>

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* send = pcap_open_live("wlan1", 65535, 1, 0, errbuf);
    if (!send) { printf("Failed: %s\n", errbuf); return 1; }

    // Minimal radiotap header
    static const uint8_t RT[] = {
        0x00,0x00,0x0c,0x00,0x04,0x80,0x00,0x00,
        0x6c,0x00,0x18,0x00
    };
    static const uint8_t MAC_HDR[] = {
        0xe0,0x00, // action no-ack
        0x00,0x00, // duration
        0xc8,0x9e,0x43,0x83,0x02,0xfe, // DA
        0x00,0x11,0x22,0x33,0x44,0x55, // SA
        0xc8,0x9e,0x43,0x83,0x02,0xfe, // BSSID
        0x00,0x00  // seq
    };

    // Test sizes from 1500 to 3000
    for (int sz = 1500; sz <= 3000; sz += 100) {
        std::vector<uint8_t> buf(sizeof(RT) + sizeof(MAC_HDR) + sz, 0xAA);
        memcpy(buf.data(), RT, sizeof(RT));
        memcpy(buf.data() + sizeof(RT), MAC_HDR, sizeof(MAC_HDR));

        int r = pcap_inject(send, buf.data(), buf.size());
        printf("size=%d result=%d %s\n", (int)buf.size(), r,
               r < 0 ? pcap_geterr(send) : "OK");
    }

    pcap_close(send);
    return 0;
}
