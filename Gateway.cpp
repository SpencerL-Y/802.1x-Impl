// Gateway.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "Gateway.h"


int exist_array[10] = {0};
int main()
{
	list<DeviceIdPair*> list = listAdaptor();
	char strMsg[] = { "Broadcasting.." };

	int id;
	cout << "select adaptor: ";
	cin >> id;
	pcap_if_t* selectedIf = selectAdaptor(id, list);
	char sndBuf[200];
	char errbuf[100];
	pcap_t* selectedAdp = pcap_open_live(selectedIf->name, 65536, 1, 1000, errbuf);
	ether_header eh;
	for (int i = 0; i < 6; i++) {
		eh.h_dest[i] = 0xff;
		// set to broadcast
		eh.h_source[i] = 0x11;
	}
	eh.type = htons(0x888f);

	gateway_hello_packet updatePack;
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
	thread bcth(&broadcast_thread, selectedAdp, sndBuf, index);

	// thread for sniffering client inet packet
	thread listenMain(&listen_main_thread, selectedIf, selectedAdp);

	listenMain.join();
	bcth.join();
}
list<DeviceIdPair*> listAdaptor()
{
	list<DeviceIdPair*> list;
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int adapNum = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_findalldevs(&alldevs, errbuf);
	int selectId = 0;
	for (d = alldevs; d; d = d->next) {
		DeviceIdPair* pair = new DeviceIdPair(d, selectId);
		list.push_back(pair);
		ifprint(d, selectId);
		selectId++;
		cout << endl;
	}

	pcap_freealldevs(alldevs);
	return list;
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

void broadcast_thread(pcap_t* selectedAdp, char* sndBuf, int index) {
	while (true) {
		if (pcap_sendpacket(selectedAdp, (u_char*)sndBuf, index) != 0) {
			cout << "error sending packet" << endl;
		}
		cout << "send updating successful" << endl;
		cout << sndBuf << endl;
		sleep(5000);
	}
}

void listen_main_thread(pcap_if_t* selectedIf, pcap_t* selectedAdp) {
	char errbuf[100];
	char* filter = (char*)"ether";
	bpf_program* fcode = setDeviceFilter(selectedIf, selectedAdp, filter);
	pcap_setfilter(selectedAdp, fcode);
	pcap_loop(selectedAdp, 0, handle_connection_main_thread, NULL);
	
}



void handle_connection_main_thread(u_char* param, const struct pcap_pkthdr* header, const u_char* packetData) {
	ether_header* eh;
	eh = (ether_header*)packetData;
	if (ntohs(eh->type) == 0x888f) {
		auth_header* auth_hdr = (auth_header*)((u_char*)packetData + 14);
		if(auth_hdr->type == 0x2){
			std::cout << "here" << std::endl;
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
    			inet_aton("192.168.1.101", (in_addr*)&client_addr);
    			ser_addr.sin_addr.s_addr = client_addr;
    			ser_addr.sin_port = htons(1188);
    			udp_startSnd_askRecv_handle(client_fd, (sockaddr*)&ser_addr, asp, );
    			close(client_fd);
			}
		}
		
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
	//TODO: add
	memset(buf, 0, 1024);
	data_len = 0;
	if (pcap_sendpacket(selectedAdp, (u_char*)buf, data_len) != 0) {
		cout << "send error" << endl;
	}
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
	//TODO: add
	memset(buf, 0, 1024);
	data_len = 0;
	if (pcap_sendpacket(selectedAdp, (u_char*)buf, data_len)) {
		cout << "send error" << endl;
	}
}


void handle_connection_thread(auth_start_packet* asp) {

}



bool checkThreadExistency(int client_id) {
	if (exist_array[client_id] == 0) {
		return false;
	}
	return true;
}

