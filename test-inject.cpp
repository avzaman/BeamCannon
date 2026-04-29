#include <pcap.h>
#include <cstdio>
#include <cstring>

static const uint8_t test_frame[] = {
	0x00, 0x00, 0x0c, 0x00,
	0x04, 0x80, 0x00, 0x00,
	0x6c, 0x00, 0x18, 0x00,
	0x40, 0x00,
	0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x00, 0x00,
	0x00, 0x00,
	0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c
};

int main(){
	char errbuf[PCAP_ERRBUF_SIZE];

	printf("[*] Opening send handle with pcap_open_live...\n");
	pcap_t* send = pcap_open_live("wlan0",65536,1,0,errbuf);
	if(!send){
		printf("[!] Failed: %s\n",errbuf);
		return 1;
	}
	printf("[+] send handle opened OK\n");

	printf("[*] Injecting test frame...\n");
	int r = pcap_inject(send,test_frame,sizeof(test_frame));
	if(r<0){
		printf("[!] Inject failed: %s\n", pcap_geterr(send));
		pcap_close(send);
		return 1;
	}
	printf("[+] Injected %d bytes OK\n",r);

	pcap_close(send);
	printf("[+] Done\n");
	return 0;
}
