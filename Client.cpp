// Client.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "Client.h"
int gatewayFound = 0;
pcap_if_t* selectedIf;
pcap_t* selectedAdp;
bpf_program* fcode;
int main()
{
	char errbuf[100];
	char* if_name = pcap_lookupdev(errbuf);
	cout << if_name << endl;
	selectedIf = listAdaptor(if_name);
	int start = 0;
	while (start != 1) {
		cout << "enter any str to start: ";
		cin >> start;
	}
	//selectedIf = selectAdaptor(id, list);
	selectedAdp = pcap_open_live(selectedIf->name, 65536, 1, 1, errbuf);
	char* filter = (char*)"ether";
	fcode = setDeviceFilter(selectedIf, selectedAdp, filter);
	pcap_setfilter(selectedAdp, fcode);
	thread findThd(&find_gateway_thread, selectedAdp);
	findThd.join();
}

pcap_if_t* listAdaptor(char* name)
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_findalldevs(&alldevs, errbuf);
	int selectId = 0;
	for (d = alldevs; d; d = d->next) {
		if(!strcmp(name, d->name)){
			return d;
		}
	}
	pcap_freealldevs(alldevs);
	return nullptr;
}

void ifprint(pcap_if_t* d, int selectId) {
	u_int32_t net_ip = ((struct sockaddr_in*)d->addresses->addr)->sin_addr.s_addr;
	u_int32_t net_mask = ((struct sockaddr_in*)d->addresses->netmask)->sin_addr.s_addr;
	struct in_addr net_ip_address;
	struct in_addr net_mask_address;
	char errbuf[PCAP_ERRBUF_SIZE];
	char ip6str[128];
	cout << "\tSelect: " << selectId << endl;
	cout << "\t" << d->name << endl;
	if (d->description) {
		cout << "\tDescription: " << d->description << endl;
	}
	cout << "\tLoopback: " << ((d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no") << endl;

	net_ip_address.s_addr = net_ip;
	char* net_ip_str = inet_ntoa(net_ip_address);
	cout << "\tNet IP Address: " << net_ip_str << endl;
	net_mask_address.s_addr = net_mask;
	char* net_mask_str = inet_ntoa(net_ip_address);
	cout << "\tNet Mask: \t" << net_mask_str << endl;
}

pcap_if_t* selectAdaptor(int id, list<DeviceIdPair*> list) {

	for (DeviceIdPair* p : list) {
		if (p->get_id() == id) {
			return p->get_pcap_if();
		}
	}
	cout << "Device id not found." << endl;
	return NULL;
}


bpf_program* setDeviceFilter(pcap_if_t* d, pcap_t* opened, char* packetFilter) {
	struct bpf_program fcode;
	u_int netmask;
	bpf_program* fcodeptr = NULL;
	if (d->addresses != NULL) {
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.s_addr;
	}
	else {
		netmask = 0xffffff;
	}
	if (pcap_compile(opened, &fcode, packetFilter, 1, netmask) < 0) {
		// unable to compile
	}
	else {

		fcodeptr = &fcode;
		return fcodeptr;
	}
	return fcodeptr;
}



void handle_ether_thread(u_char* param, const struct pcap_pkthdr* header, const u_char* packetData) {
	ether_header* eh;
	eh = (ether_header*)packetData;
	auth_header* ah = (auth_header*)((u_char*)packetData + 14);

	if (ntohs(eh->type) == 0x888f) {
		if (ah->type == 0x1) {
			// solve for broadcast
			auth_hello_packet* ghp = (auth_hello_packet*)((u_char*)packetData + 14);
			cout << "Broadcast received" << endl;
			cout << packetData << endl;
			cout << ghp->gateway_info.mac[0] << endl;
			if (ghp->gateway_id == 0x8) {
				cout << "id correct" << endl;
				gatewayFound = 1;
				thread th(&handle_start_thread, selectedAdp);
				th.join();
			}
		} else if(ah->type == 0x3){
			auth_ask_packet* gap = (auth_ask_packet*)((u_char*)packetData + 14);
			cout << "Server ask received" << endl;
			cout << packetData << endl;
			thread th(&handle_ask_thread, selectedAdp);
			th.join();

		} else if(ah->type == 0x5){
			cout << "Server response received" << endl;
			//TODO: add handle.
		}
		
	}
}

void handle_start_thread(pcap_t* selectedAdp) {
	ether_header eh;
	auth_start_packet authStart;

	memset(&eh, 0, sizeof(eh));
	memset(&authStart, 0, sizeof(authStart));
	eh.type = htons(0x888f);
	for (int i = 0; i < 6; i++) {
		eh.h_dest[i] = 0xff;
		eh.h_source[i] = 0x22;
	}
	authStart.auth_hdr.type = 0x2;
	authStart.client_id = 0x1;
	for (int i = 0; i < 6; i++) {
		authStart.client_info.mac[i] = 0x22;
	}
	authStart.gateway_id = 0x8;
	char sndBuf[200];
	memset(sndBuf, 0, 200);
	int index = 0;
	memcpy(sndBuf + index, &eh, sizeof(eh));
	index += sizeof(eh);
	memcpy(sndBuf + index, &authStart, sizeof(authStart));
	index += sizeof(authStart);
	if (index <= 42) {
		index = 42;
	}
	cout << "auth start id: " << (int)authStart.client_id << " size: " << index << endl;
	if (pcap_sendpacket(selectedAdp, (u_char*)sndBuf, index) != 0) {
		cout << "send buf error" << endl;
	}
	
	cout << "send authStart successful" << endl;
	cout << "sent size: " << index << endl;
	cout << "buffer sent: " << sndBuf << endl;

}

void handle_ask_thread(pcap_t* selectedAdp){
	ether_header eh;
	auth_answer_packet authAnswer;

	memset(&eh, 0, sizeof(eh));
	memset(&authAnswer, 0, sizeof(authAnswer));
	eh.type = htons(0x888f);
	for (int i = 0; i < 6; i++) {
		eh.h_dest[i] = 0xff;
		eh.h_source[i] = 0x11;
	}
	authAnswer.auth_hdr.type = 0x4;
	authAnswer.client_id = 0x1;
	authAnswer.random_num_decrypted = htonl(4096);
	char sndBuf[200];
	memset(sndBuf, 0, 200);
	int index = 0;
	memcpy(sndBuf + index, &eh, sizeof(eh));
	index += sizeof(eh);
	memcpy(sndBuf + index, &authAnswer, sizeof(authAnswer));
	index += sizeof(authAnswer);
	if (index <= 42) {
		index = 42;
	}
	cout << "auth start id: " << (int)authAnswer.client_id << " size: " << index << endl;
	if (pcap_sendpacket(selectedAdp, (u_char*)sndBuf, index) != 0) {
		cout << "send buf error" << endl;
	}
	
	cout << "send authStart successful" << endl;
	cout << "sent size: " << index << endl;
	cout << "buffer sent: " << sndBuf << endl;
}

void find_gateway_thread(pcap_t* selectedAdp) {
	while (!gatewayFound) {
		pcap_loop(selectedAdp, 1, handle_ether_thread, NULL);
	}
}

