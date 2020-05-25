// Server.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "Server.h"

void udp_startRecv_askSnd_answerRecv_responseSnd_handle(int fd) {
	char buf[1024];
	socklen_t len;
	int count;
	struct sockaddr_in gateway_addr;
	// use for remembering the otherside
	memset(buf, 0, 1024);
	len = sizeof(gateway_addr);
	// recv start part
	count = recvfrom(fd, buf, 1024, 0, (struct sockaddr*) & gateway_addr, &len);
	if (count == -1) {
		std::cout << "recv data failed" << std::endl;
		return;
	}
	auth_start_packet* asp = (auth_start_packet*)buf;
	if(asp->auth_hdr.type == 0x1){
		cout << "Server received start packet" << endl;
	}
	std::cout << buf << endl;
	// send ask part
	auth_ask_packet aap;
	aap.auth_hdr.type = 0x3;
	aap.client_id = asp->client_id;
	aap.server_id = 0x8;
	aap.random_num_encrypted = htonl(4096);
	memset(buf, 0, 1024);
	memcpy(buf, &aap, sizeof(aap));
	sendto(fd, buf, 1024, 0, (struct sockaddr*) & gateway_addr, len);
	std::cout << "Send gateway ask: " << buf << std::endl;
	// recv answer part
	memset(buf, 0, 1024);
	count = recvfrom(fd, buf, 1024, 0, (struct sockaddr*) & gateway_addr, &len);
	if (count == -1) {
		std::cout << "recv data failed" << std::endl;
		return;
	}
	std::cout << "Receive gateway answer: " << buf << std::endl;
	auth_answer_packet* aAnsP = (auth_answer_packet*)buf;
	if(aAnsP->auth_hdr.type == 0x3){
		cout << "Server receive answer packet" << endl;
	}
	identifier client_id = aAnsP->client_id;
	// send response part
	memset(buf, 0, 1024);
	auth_response_packet arep;
	arep.auth_hdr.type = 0x5;
	arep.client_id = client_id;
	arep.client_ip_private_key = 0;
	arep.server_id = 0x8;
	memcpy(buf, &arep, sizeof(arep));
	sendto(fd, buf, 1024, 0, (struct sockaddr*) & gateway_addr, len);
	std::cout << "Send gateway response: Connection built" << buf << std::endl;
	// connection build
}


int main()
{
	int server_fd, ret;
	struct sockaddr_in ser_addr;
	server_fd = socket(AF_INET, SOCK_DGRAM, 0);
	// construct socket
	if (server_fd < 0) {
		std::cout << "create socket failed";
		return 0;
	}
	memset(&ser_addr, 0, sizeof(ser_addr));
	ser_addr.sin_family = AF_INET;in_addr_t addrServ;
    inet_aton(IP_STR, (in_addr*)&addrServ);
    ser_addr.sin_addr.s_addr = (uint32_t)addrServ;
	ser_addr.sin_port = htons(1188);
	ret = bind(server_fd, (struct sockaddr*) & ser_addr, sizeof(ser_addr));
	if (ret < 0) {
		std::cout << "bind failure" << std::endl;
		return -1;
	}
	udp_startRecv_askSnd_answerRecv_responseSnd_handle(server_fd);
	close(server_fd);
	return 0;
}
