﻿// Gateway.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "Gateway.h"


int exist_array[10] = {0};
pcap_t* selectedAdp;
int main()
{
	cout << "list adp" << endl;
	//list<DeviceIdPair*> list = listAdaptor();
	cout << "end list" << endl;
	char strMsg[] = { "Broadcasting.." };

	int id;
	cout << "select adaptor: ";
	//pcap_if_t* selectedIf = selectAdaptor(id, list);
	char errbuf[100];
	char* if_name = pcap_lookupdev(errbuf);
	cout << if_name << endl;
	pcap_if_t* selectedIf = listAdaptor(if_name);
	cout << selectedIf->name << endl;
	char sndBuf[200];
	
	cout << "selectedAdp" << endl;
	selectedAdp = pcap_open_live(if_name, 65536, 1, 1000, errbuf);
	cout << "selectedEnd" << endl;
	ether_header eh;
	for (int i = 0; i < 6; i++) {
		eh.h_dest[i] = 0xff;
		// set to broadcast
		eh.h_source[i] = 0x11;
	}
	eh.type = htons(0x888f);

	auth_hello_packet updatePack;
	long addr = ((struct sockaddr_in*)selectedIf->addresses->addr)->sin_addr.s_addr;
	updatePack.gateway_info.ip.byte1 = 0xff000000 & addr >> 6;
	updatePack.gateway_info.ip.byte2 = 0x00ff0000 & addr >> 4;
	updatePack.gateway_info.ip.byte3 = 0x0000ff00 & addr >> 2;
	updatePack.gateway_info.ip.byte4 = 0x000000ff & addr;
	for (int i = 0; i < 6; i++) {
		updatePack.gateway_info.mac[i] = 0x11;
	}
	updatePack.gateway_id = 0x8;
	updatePack.auth_hdr.type = 1;
	int index = 0;
	memcpy(sndBuf, &eh, sizeof(eh));
	index = sizeof(eh);
	cout << index << endl;
	memcpy(&sndBuf[index], &updatePack, sizeof(updatePack));
	index += sizeof(updatePack);
	cout << index << endl;
	// thread for broadcasting hello packets
	//thread bcth(&broadcast_thread, selectedAdp, sndBuf, index);
	broadcast_thread(selectedAdp, sndBuf, index);
	// thread for sniffering client inet packet
	thread listenMain(&listen_main_thread, selectedIf, selectedAdp);
	//listen_main_thread(selectedIf, selectedAdp);
	listenMain.join();
	//bcth.join();

}
// list adaptor for windows version
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

/*pcap_if_t* selectAdaptor(int id, list<DeviceIdPair*> list) {

	for (DeviceIdPair* p : list) {
		if (p->get_id() == id) {
			return p->get_pcap_if();
		}
	}
	cout << "Device id not found." << endl;
	return NULL;
}*/

bpf_program* setDeviceFilter(pcap_if_t* d, pcap_t* opened, char* packetFilter) {
	struct bpf_program fcode;
	u_int netmask;
	bpf_program* fcodeptr = NULL;
	netmask = 0xffffff;
	if (pcap_compile(opened, &fcode, packetFilter, 1, netmask) < 0) {
		// unable to compile
		cout << "unable to compile" << endl;
	}
	else {

		fcodeptr = &fcode;
		return fcodeptr;
	}
	return fcodeptr;
}

void broadcast_thread(pcap_t* selectedAdp, char* sndBuf, int index) {
	cout << "broadcast thread" << endl;
	int i = 1;
	while (i-- > 0) {
		if (pcap_sendpacket(selectedAdp, (u_char*)sndBuf, index) != 0) {
			cout << "error sending packet" << endl;
		}
		cout << "send updating successful" << endl;
		cout << sndBuf << endl;
		sleep(1);
	}
}

void listen_main_thread(pcap_if_t* selectedIf, pcap_t* selectedAdp) {
	cout << "listen main thread" << endl;
	char errbuf[100];
	char* filter = (char*)"ether";
	bpf_program* fcode = setDeviceFilter(selectedIf, selectedAdp, filter);
	pcap_setfilter(selectedAdp, fcode);
	pcap_loop(selectedAdp, 0, handle_connection_main_thread, NULL);
	
	cout << "listen main thread end" << endl;
}



void handle_connection_main_thread(u_char* param, const struct pcap_pkthdr* header, const u_char* packetData) {
	
	
	ether_header* eh;
	eh = (ether_header*)packetData;
	if (ntohs(eh->type) == 0x888f) {
		cout << "handle connection thread" << endl;
		auth_header* auth_hdr = (auth_header*)((u_char*)packetData + 14);
		if(auth_hdr->type == 0x2){
			std::cout << "auth_hdr type: 0x2" << std::endl;
			cout << "start reveived" << endl;
			auth_start_packet* asp = (auth_start_packet*)((u_char*)packetData + 14);
			cout << packetData << endl;
			cout << "Client identifier: " << (int)asp->client_id << endl;
			bool check = checkThreadExistency((int)asp->client_id);
			if (!check) {
				exist_array[asp->client_id] = 1;
				cout << "create socket connection to server" << endl;
				//TODO: add ethernet packet handle here
				int gateway_fd;
   				struct sockaddr_in ser_addr;
   				gateway_fd = socket(AF_INET, SOCK_DGRAM, 0);
    			if(gateway_fd < 0){
    			    std::cout << "create socket failed" << std::endl;
    			    return;
    			}
    			memset(&ser_addr, 0, sizeof(ser_addr));
    			ser_addr.sin_family = AF_INET;
    			in_addr_t client_addr;
    			inet_aton(IP_STR, (in_addr*)&client_addr);
    			ser_addr.sin_addr.s_addr = client_addr;
    			ser_addr.sin_port = htons(1188);
    			udp_startSnd_askRecv_handle(gateway_fd, (sockaddr*)&ser_addr, asp, selectedAdp);
    			close(gateway_fd);
			}
		} else if(auth_hdr->type == 0x4){
			std::cout << "auth_hdr type: 0x4" << std::endl;
			cout << "answer received" << endl;
			auth_answer_packet* aap = (auth_answer_packet*)((u_char*)packetData + 14);
			cout << packetData << endl;
			cout << "client identifier: " << aap->client_id << endl;
			bool check = checkThreadExistency((int)aap->client_id);
			if (check) {
				cout << "create socket connection to server" << endl;
				//TODO: add ethernet packet handle here
				int gateway_fd;
   				struct sockaddr_in ser_addr;
   				gateway_fd = socket(AF_INET, SOCK_DGRAM, 0);
    			if(gateway_fd < 0){
    			    std::cout << "create socket failed" << std::endl;
    			    return;
    			}
    			memset(&ser_addr, 0, sizeof(ser_addr));
    			ser_addr.sin_family = AF_INET;
    			in_addr_t client_addr;
    			inet_aton(IP_STR, (in_addr*)&client_addr);
    			ser_addr.sin_addr.s_addr = client_addr;
    			ser_addr.sin_port = htons(1188);
    			udp_answerSnd_responseRecv_handle(gateway_fd, (sockaddr*)&ser_addr, aap, selectedAdp);
    			close(gateway_fd);
			} else {
				cout << "ERROR: CLIENT NOT STARTED" << endl;
			}
		}
		cout << "handle connection thread end" << endl;
	}
	
}

void udp_startSnd_askRecv_handle(int fd, struct sockaddr* dst, auth_start_packet *asp, pcap_t* selectedAdp) {
	// start socket handle
	socklen_t len;
	struct sockaddr_in src;
	char buf[1024];
	memset(buf, 0, 1024);
	int data_len = sizeof(*asp);
	memcpy(buf, asp, data_len);
	len = sizeof(*dst);
	std::cout << "Gateway: send start packet " << buf << std::endl;
	sendto(fd, buf, 1024, 0, dst, len);
	memset(buf, 0, 1024);
	recvfrom(fd, buf, 1024, 0, (struct sockaddr*) & src, &len);
	std::cout << "Gateway: recv ask packet " << buf << std::endl;

	// transmit the data to client
	char ether_buf[1024];
	memset(ether_buf, 0, 1024);
	ether_header eh;
	eh.type = htons(0x888f);
	for (int i = 0; i < 6; i++) {
		eh.h_dest[i] = 0xff;
		eh.h_source[i] = 0x11;
	}
	auth_ask_packet* aap = (auth_ask_packet*)buf;
	if(aap->auth_hdr.type == 0x3){
		cout << "ask packet received" << endl;
	}
	int index = 0;
	memcpy(ether_buf, &eh, sizeof(eh));
	index += sizeof(eh);
	memcpy(ether_buf + index, buf, sizeof(*aap));
	index += sizeof(*aap);
	if (pcap_sendpacket(selectedAdp, (u_char*)ether_buf, index) != 0) {
		cout << "send error" << endl;
	}
	cout << "gateway send ether ask packet:" << endl;
	cout << ether_buf << endl;
}

void udp_answerSnd_responseRecv_handle(int fd, struct sockaddr* dst, auth_answer_packet* aap, pcap_t* selectedAdp) {
	// start socket handle
	socklen_t len;
	struct sockaddr_in src;
	char buf[1024];
	memset(buf, 0, 1024);
	int data_len = sizeof(*aap);
	memcpy(buf, aap, data_len);
	len = sizeof(*dst);
	std::cout << "Gateway: send answer packet "  << buf << std::endl;
	sendto(fd, buf, 1024, 0, dst, len);
	memset(buf, 0, 1024);
	recvfrom(fd, buf, 1024, 0, (struct sockaddr*) & src, &len);
	std::cout << "Gateway: recv response packet " << buf << std::endl;
	auth_response_packet* arep = (auth_response_packet*)buf;
	if(arep->auth_hdr.type = 0x5){
		cout << "response packet received" << endl;
	}
	// transmit data to client
	char ether_buf[1024];
	memset(ether_buf, 0, 1024);
	int index = 0;
	ether_header eh;
	eh.type = htons(0x888f);
	for (int i = 0; i < 6; i++) {
		eh.h_dest[i] = 0xff;
		eh.h_source[i] = 0x11;
	}
	memcpy(ether_buf, &eh, sizeof(eh));
	index += sizeof(eh);
	memcpy(ether_buf + index, buf, sizeof(*arep));
	index += sizeof(*arep);
	if (pcap_sendpacket(selectedAdp, (u_char*)ether_buf, index)) {
		cout << "send error" << endl;
	}
}



bool checkThreadExistency(int client_id) {
	if (exist_array[client_id] == 0) {
		return false;
	}
	return true;
}

