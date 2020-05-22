// Server.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "Server.h"

void udp_startRecv_askSnd_answerRecv_responseSnd_handle(int fd) {
	char buf[1024];
	socklen_t len;
	int count;
	struct sockaddr_in gateway_addr;
	// use for remember the otherside
	memset(buf, 0, 1024);
	len = sizeof(gateway_addr);
	// recv start part
	count = recvfrom(fd, buf, 1024, 0, (struct sockaddr*) & gateway_addr, &len);
	if (count == -1) {
		std::cout << "recv data failed" << std::endl;
		return;
	}
	std::cout << buf << endl;
	std::cout << "Reiceive gateway start: " << buf << std::endl;
	// send ask part
	// TODO: add 
	memset(buf, 0, 1024);
	sendto(fd, buf, 1024, 0, (struct sockaddr*) & gateway_addr, len);
	std::cout << "Send gateway ask: " << buf << std::endl;
	// recv answer part
	// TODO: add
	memset(buf, 0, 1024);
	count = recvfrom(fd, buf, 1024, 0, (struct sockaddr*) & gateway_addr, &len);
	if (count == -1) {
		std::cout << "recv data failed" << std::endl;
		return;
	}
	std::cout << "Receive gateway answer: " << buf << std::endl;

	// send response part
	// TODO: add
	memset(buf, 0, 1024);
	sendto(fd, buf, 1024, 0, (struct sockaddr*) & gateway_addr, len);
	std::cout << "Send gateway response: " << buf << std::endl;
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
