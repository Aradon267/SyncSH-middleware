#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define strncasecmp(x,y,z) _strnicmp(x,y,z)
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <iostream>
#include <conio.h>
#include <chrono>
#include <thread>
#include <fstream> 
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <WinSock2.h>
#include <filesystem>
#include "sole.hpp"
#include "Helper.h"
#include "JsonResponsePacketSerializer.h"
#include "JsonRequestPacketDeserializer.h"

using namespace std;


class SyncSHClient
{
public:
	SyncSHClient();
	int exeCommand(ssh_session session, JsonRequestPacketDeserializer::CommandRequest command, SOCKET sock);
	int shell_session(ssh_session session);
	int uploadFile(ssh_session session, JsonRequestPacketDeserializer::UploadRequest upload, SOCKET sock);
	int downloadFile(ssh_session session, JsonRequestPacketDeserializer::DownloadRequest download, SOCKET sock);
	int verify_knownhost(ssh_session session, SOCKET sock, JsonRequestPacketDeserializer::FPRequest FP);
	int getSystemOS(ssh_session session, SOCKET sock, JsonRequestPacketDeserializer::OSRequest OS);
	int getSystemOSNotWin(ssh_session session, SOCKET sock, JsonRequestPacketDeserializer::OSRequest OS);
	int getInteractiveShell(ssh_session session, JsonRequestPacketDeserializer::GetShellRequest shell);
	int commandShell(JsonRequestPacketDeserializer::CommandShellRequest shell, bool close);
	JsonResponsePacketSerializer* serializer;
	vector<unsigned char> currResp;
	ssh_channel interactiveShell;
};

