#pragma once

#include <iostream>

#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#define _SILENCE_STDEXT_HASH_DEPRECATION_WARNINGS 1

#include <stdio.h>
#include <string>
#include <list>
#include <thread>
#include <pcap/pcap.h>
#include "packet.h"
#include <memory.h>
#include <unistd.h>
#include "config.h"
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "Lib/x64/wpcap.lib")
using namespace std;
void udp_startRecv_askSnd_answerRecv_responseSnd_handle(int fd);