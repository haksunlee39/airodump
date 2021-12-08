#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include <thread>
#include <unistd.h>
#include "mac.h"

#include "main.h"

void packet_view(unsigned char *args,const struct pcap_pkthdr *h,const unsigned char *p);

#define SNAP_LEN 3000


typedef struct beaconInfo{
	int count;
	char essid[64];
} beaconInfo;

std::map<Mac, beaconInfo> beaconDatas;
bool stopThread = false;

void printBeaconData()
{
	while(!stopThread)
	{
		system("clear");
		printf("BSSID             Beacons  ESSID\n\n");
		
		for(auto data: beaconDatas)
		{
			printf("%s ", std::string(data.first).data());
			printf("%7d  ", data.second.count);
			printf("%s", data.second.essid);
			printf("\n");
		}
		sleep(1);
	}
}

void insertIntoData(const uint8_t *bssid, char* essidBuffer)
{
	Mac newMac = Mac(bssid);
	//printf("%s \n", std::string(newMac).data());
	//printf("%s \n", std::string(beaconDatas.begin()->first).data());
	if (beaconDatas.count(newMac))
	{
		beaconDatas[newMac].count++;
	}
	else
	{
		beaconInfo newInfo;
		newInfo.count = 1;
		strcpy(newInfo.essid, essidBuffer);
		beaconDatas.insert({newMac, newInfo});
	}
}

void packet_view(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
	const uint8_t *bssid; // a place to put our BSSID \ these are bytes
	const uint8_t *essid; // a place to put our ESSID / from the packet
	
	char essidBuffer[64]; // 63 is the limit
	int offset = 0;
	RadiotapHeader *rtaphdr;
	
	offset = rtaphdr->it_len;
	bssid = packet + 40; // store the BSSID/AP MAC addr, 36 byte offset is transmitter address
	essid = packet + 62; // store the ESSID/Router name too
	int i = 0;
	while(essid[i] > 0x1){
		essidBuffer[i] = essid[i]; // store the ESSID bytes in *essidBuffer
		i++; // POSTFIX
	}
	essidBuffer[i] = '\0';
	
	//printf("BSSID string: %02X:%02X:%02X:%02X:%02X:%02X\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
	//printf("ESSID string: %s\n", essidBuffer);
	
	insertIntoData(bssid, essidBuffer);

}

int main(int argc, char **argv)
{
	char *dev = NULL;                       /* capture device name */
        char errbuf[PCAP_ERRBUF_SIZE];          /* error buffer */
        pcap_t *handle;                         /* packet capture handle */

        char filter_exp[] = "wlan type mgt subtype beacon"; /* filter expression [3] */
       // char filter_exp[] = "ip"; /* filter expression [3] */
        struct bpf_program fp;                  /* compiled filter program (expression) */
        bpf_u_int32 mask;                       /* subnet mask */
        bpf_u_int32 net;                        /* ip */
        int num_packets = 10;                   /* number of packets to capture */
        
        std::thread t_object(printBeaconData);


        /* check for capture device name on command-line */
        if (argc == 2) {
                dev = argv[1];
        }
        else if (argc > 2) {
                fprintf(stderr, "error: unrecognized command-line options\n\n");
                exit(EXIT_FAILURE);
        }
        else {
                /* find a capture device if not specified on command-line */
                dev = pcap_lookupdev(errbuf);
                if (dev == NULL) {
                        fprintf(stderr, "Couldn't find default device: %s\n",
                            errbuf);
                        exit(EXIT_FAILURE);
                }
        }
            /* get network number and mask associated with capture device */
                if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                    dev, errbuf);
                net = 0;
                mask = 0;
        }

        /* print capture info */
        printf("Device: %s\n", dev);
        //printf("Number of packets: %d\n", num_packets);
        printf("Filter expression: %s\n", filter_exp);

        /* open capture device */
        handle = pcap_open_live(dev, SNAP_LEN, 1, -1, errbuf);
        if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                exit(EXIT_FAILURE);
        }

        /* for  Ethernet device change the type to DLT_EN10MB */
        /* your wlan device need to supprot this link layer type otherwise failure */
        if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO) {
                fprintf(stderr, "%s is not an Wlan packet\n", dev);
               exit(EXIT_FAILURE);
        }

        /* compile the filter expression */
        if (pcap_compile(handle, &fp, filter_exp, 1,PCAP_NETMASK_UNKNOWN) == -1) {
                fprintf(stderr, "Couldn't parse filter %s: %s\n",
                    filter_exp, pcap_geterr(handle));
                exit(EXIT_FAILURE);
        }

        /* apply the compiled filter */
        if (pcap_setfilter(handle, &fp) == -1) {
                fprintf(stderr, "Couldn't install filter %s: %s\n %s: %s\n",
                    filter_exp, pcap_geterr(handle));
                exit(EXIT_FAILURE);
        }
        /* now we can set our callback function */
        pcap_loop(handle, 0, packet_view, NULL);

        /* cleanup */
        pcap_freecode(&fp);
        pcap_close(handle);
        stopThread = true;
        t_object.join();

        printf("\nCapture complete.\n");

return 0;
}

/*
sudo ifconfig wlx705dccfe9a78 down
sudo iwconfig wlx705dccfe9a78 mode monitor
sudo ifconfig wlx705dccfe9a78 up
make
sudo ./airodump wlx705dccfe9a78
*/;
