#pragma once
#include <WinSock2.h>
#include <Windows.h>
#include <thread>
#include "SyncSHClient.h"
#include <queue>

class Server
{
public:
	Server();
	~Server();
	void serve(int port);
	void handleRequests(string msg, SOCKET clientSocket);
	void handleMessageQueue(SOCKET clientSocket);
	map<string, ssh_session> m_clients;
	map<string, ssh_channel> m_shells;
	queue<string> messageQueue;
private:
	void acceptClient();
	void clientHandler(SOCKET clientSocket);
	bool isDisconnected;
	SOCKET _serverSocket;
};

