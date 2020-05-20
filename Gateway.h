// Gateway.cpp : ���ļ����� "main" ����������ִ�н��ڴ˴���ʼ��������
//

#include <iostream>

#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#define _SILENCE_STDEXT_HASH_DEPRECATION_WARNINGS 1
#include <stdio.h>
#include <string>
#include <pcap/pcap.h>
#include <list>
#include <thread>
#include <hash_map>
#include <memory.h>
#include <unistd.h>
#include "packet.h"
#include "DeviceIdPair.h"
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "Lib/x64/wpcap.lib")
using namespace std;

list<DeviceIdPair*> listAdaptor();
void ifprint(pcap_if_t* d, int selectId);
pcap_if_t* selectAdaptor(int id, list<DeviceIdPair*> list);
void broadcast_thread(pcap_t* selectedAdp, char* sndBuf, int index);
void listen_main_thread(pcap_if_t* selectedIf, pcap_t* selectedAdp);
bpf_program* setDeviceFilter(pcap_if_t* d, pcap_t* opened, char* packetFilter);
bool checkThreadExistency(int client_id);
void handle_connection_main_thread(u_char* param, const struct pcap_pkthdr* header, const u_char* packetData);
void handle_connection_thread(auth_start_packet* asp);
void udp_answerSnd_responseRecv_handle(int fd, struct sockaddr* dst, auth_answer_packet* aap, pcap_t* selectedAdp);
void udp_startSnd_askRecv_handle(int fd, struct sockaddr* dst, auth_start_packet* asp, pcap_t* selectedAdp);