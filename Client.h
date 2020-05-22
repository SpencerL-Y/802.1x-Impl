
#include <iostream>

#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#include <stdio.h>
#include <string>
#include <pcap/pcap.h>
#include <list>
#include <thread>
#include <memory.h>
#include <unistd.h>
#include "packet.h"
#include "DeviceIdPair.h"
#include "config.h"
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "Lib/x64/wpcap.lib")
using namespace std;
pcap_if_t* listAdaptor();
void ifprint(pcap_if_t* d, int selectId);
//pcap_if_t* selectAdaptor(int id, list<DeviceIdPair*> list);
bpf_program* setDeviceFilter(pcap_if_t* d, pcap_t* opened, char* packetFilter);
void handle_ether_thread(u_char* param, const struct pcap_pkthdr* header, const u_char* packetData);
void find_gateway_thread(pcap_t* selectedAdp);
void handle_start_thread(pcap_t* selectedAdp);
void handle_ask_thread(pcap_t* selectedAdp);