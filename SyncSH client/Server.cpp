#pragma comment(lib, "Ws2_32.lib")
#include "Server.h"
#include "Helper.h"
#include "JsonRequestPacketDeserializer.h"
#include "JsonResponsePacketSerializer.h"
#include <exception>
#include <iostream>
#include <string>
#include <thread>

Server::Server()
{

	// this server use TCP. that why SOCK_STREAM & IPPROTO_TCP
	// if the server use UDP we will use: SOCK_DGRAM & IPPROTO_UDP
	_serverSocket = socket(AF_INET,  SOCK_STREAM,  IPPROTO_TCP); 

	if (_serverSocket == INVALID_SOCKET)
		throw std::exception(__FUNCTION__ " - socket");
    isDisconnected = false;
}

Server::~Server()
{
	try
	{
		// the only use of the destructor should be for freeing 
		// resources that was allocated in the constructor
		closesocket(_serverSocket);
	}
	catch (...) {}
}

void Server::serve(int port)
{
	
	struct sockaddr_in sa = { 0 };
	
	sa.sin_port = htons(port); // port that server will listen for
	sa.sin_family = AF_INET;   // must be AF_INET
	sa.sin_addr.s_addr = INADDR_ANY;    // when there are few ip's for the machine. We will use always "INADDR_ANY"

	// Connects between the socket and the configuration (port and etc..)
	if (::bind(_serverSocket, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR)
		throw std::exception(__FUNCTION__ " - bind");
	
	// Start listening for incoming requests of clients
	if (listen(_serverSocket, SOMAXCONN) == SOCKET_ERROR)
		throw std::exception(__FUNCTION__ " - listen");
	std::cout << "Listening on port " << port << std::endl;

	while (true)
	{
		// the main thread is only accepting clients 
		// and add then to the list of handlers
		std::cout << "Waiting for client connection request" << std::endl;
		acceptClient();
	}
}

void Server::handleRequests(string msg, SOCKET clientSocket)
{
    ssh_session my_ssh_session;
    std::ifstream fin("commands.json");
    json j;
    fin >> j;

    //parse requests
    json requests = json::parse(j["request"].dump());

    //parse responses
    json responses = json::parse(j["response"].dump());
    json connectJson = json::parse(responses["connect"].dump());
    json commandJson = json::parse(responses["sendCommand"].dump());
    json downloadJson = json::parse(responses["download"].dump());
    json uploadJson = json::parse(responses["upload"].dump());
    json OSJson = json::parse(responses["getOSInfo"].dump());
    json FPJson = json::parse(responses["collectFingerprint"].dump());
    json getInteractiveJson = json::parse(responses["getInteractiveShell"].dump());
    json commandInteractiveJson = json::parse(responses["sendInteractiveShellCommand"].dump());
    json closeInteractiveJson = json::parse(responses["closeInteractiveShell"].dump());

    JsonResponsePacketSerializer* serializer = new JsonResponsePacketSerializer();
    SyncSHClient* sshClient = new SyncSHClient();

    JsonRequestPacketDeserializer::Base req;
    int rc;
    int pick = 0;
    const char* password;
    string command;
    string pass;
    int port = 22;

    // stateless
    req = JsonRequestPacketDeserializer::deserializeBase(msg.c_str());
    try{
        if (req.type == requests["connect"].dump()) {
            cout << "connect" << endl;
            JsonRequestPacketDeserializer::LoginRequest reqLog = JsonRequestPacketDeserializer::deserializeLoginRequest(req.d.c_str());
            my_ssh_session = ssh_new();
            if (my_ssh_session == NULL) {
                throw exception();
                JsonResponsePacketSerializer::LoginResponse respLoging{ "Bad",reqLog.accountId };
                vector<unsigned char> respLog = serializer->serializeLoginResponse(respLoging, connectJson["fail"].dump().substr(1, connectJson["fail"].dump().size() - 2));
                this->messageQueue.push(string(respLog.begin(), respLog.end()));
            }
            port = stoi(reqLog.serverPort);
            ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, reqLog.serverIP.c_str());
            ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, reqLog.accountName.c_str());
            ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);
            ssh_options_set(my_ssh_session, SSH_OPTIONS_CIPHERS_C_S, "aes256-ctr");
            ssh_options_set(my_ssh_session, SSH_OPTIONS_CIPHERS_S_C, "aes256-ctr");
            ssh_options_set(my_ssh_session, SSH_OPTIONS_KEY_EXCHANGE, "diffie-hellman-group-exchange-sha256");
            ssh_options_set(my_ssh_session, SSH_OPTIONS_HOSTKEYS, "ssh-rsa");
            ssh_options_set(my_ssh_session, SSH_OPTIONS_HMAC_C_S, "hmac-sha2-256");
            ssh_options_set(my_ssh_session, SSH_OPTIONS_HMAC_S_C, "hmac-sha2-256");
            ssh_options_set(my_ssh_session, SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES, "ssh-rsa");

            rc = ssh_connect(my_ssh_session);
            if (rc != SSH_OK)
            {
                fprintf(stderr, "Error connecting to localhost: %s\n",
                    ssh_get_error(my_ssh_session));
                JsonResponsePacketSerializer::LoginResponse respLoging{ ssh_get_error(my_ssh_session),reqLog.accountId };
                vector<unsigned char> respLog = serializer->serializeLoginResponse(respLoging, connectJson["fail"].dump().substr(1, connectJson["fail"].dump().size() - 2));
                this->messageQueue.push(string(respLog.begin(), respLog.end()));
                throw exception();
            }

            rc = ssh_userauth_password(my_ssh_session, NULL, reqLog.accountPassword.c_str());
            if (rc != SSH_AUTH_SUCCESS)
            {
                fprintf(stderr, "Authentication failed: %s\n",
                    ssh_get_error(my_ssh_session));
                JsonResponsePacketSerializer::LoginResponse respLoging{ ssh_get_error(my_ssh_session),reqLog.accountId };
                vector<unsigned char> respLog = serializer->serializeLoginResponse(respLoging, connectJson["fail"].dump().substr(1, connectJson["fail"].dump().size() - 2));
                this->messageQueue.push(string(respLog.begin(), respLog.end()));
                throw exception();
            }
            this->m_clients.insert(pair<string, ssh_session>(reqLog.accountId, my_ssh_session));
            JsonResponsePacketSerializer::LoginResponse respLoging{ "Good",reqLog.accountId };
            vector<unsigned char> respLog = serializer->serializeLoginResponse(respLoging, connectJson["success"].dump().substr(1, connectJson["success"].dump().size() - 2));
            this->messageQueue.push(string(respLog.begin(), respLog.end()));
        }
        else if (req.type == requests["collectFingerprint"].dump()) {
            cout << "FP" << endl;
            JsonRequestPacketDeserializer::FPRequest reqFP = JsonRequestPacketDeserializer::deserializeFPRequest(req.d.c_str());
            my_ssh_session = ssh_new();
            if (my_ssh_session == NULL) {
                throw exception();
                JsonResponsePacketSerializer::FPResponse respFP{ "Bad",reqFP.accountId };
                vector<unsigned char> respLog = serializer->serializeFPResponse(respFP, FPJson["fail"].dump().substr(1, FPJson["fail"].dump().size() - 2));
                this->messageQueue.push(string(respLog.begin(), respLog.end()));
            }
            port = stoi(reqFP.serverPort);
            ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, reqFP.serverIP.c_str());
            ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);
            ssh_options_set(my_ssh_session, SSH_OPTIONS_CIPHERS_C_S, "aes256-ctr");
            ssh_options_set(my_ssh_session, SSH_OPTIONS_CIPHERS_S_C, "aes256-ctr");
            ssh_options_set(my_ssh_session, SSH_OPTIONS_KEY_EXCHANGE, "diffie-hellman-group-exchange-sha256");
            ssh_options_set(my_ssh_session, SSH_OPTIONS_HOSTKEYS, "ssh-rsa");
            ssh_options_set(my_ssh_session, SSH_OPTIONS_HMAC_C_S, "hmac-sha2-256");
            ssh_options_set(my_ssh_session, SSH_OPTIONS_HMAC_S_C, "hmac-sha2-256");
            ssh_options_set(my_ssh_session, SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES, "ssh-rsa");

            rc = ssh_connect(my_ssh_session);
            if (rc != SSH_OK)
            {
                fprintf(stderr, "Error connecting to localhost: %s\n",
                    ssh_get_error(my_ssh_session));
                JsonResponsePacketSerializer::FPResponse respFP{ ssh_get_error(my_ssh_session),reqFP.accountId };
                vector<unsigned char> respLog = serializer->serializeFPResponse(respFP, FPJson["fail"].dump().substr(1, FPJson["fail"].dump().size() - 2));
                this->messageQueue.push(string(respLog.begin(), respLog.end()));
                throw exception();
            }

            rc = sshClient->verify_knownhost(my_ssh_session, clientSocket, reqFP);
            if (rc != SSH_OK) {
                fprintf(stderr, "Error connecting to localhost: %s\n",
                    ssh_get_error(my_ssh_session));
                JsonResponsePacketSerializer::FPResponse respFP{ ssh_get_error(my_ssh_session),reqFP.accountId };
                vector<unsigned char> respLog = serializer->serializeFPResponse(respFP, FPJson["fail"].dump().substr(1, FPJson["fail"].dump().size() - 2));
                this->messageQueue.push(string(respLog.begin(), respLog.end()));
                throw exception();
            }
            this->messageQueue.push(string(sshClient->currResp.begin(), sshClient->currResp.end()));

            //dissconnected = true;
        }
        else if (req.type == requests["sendCommand"].dump()) {
            cout << "command" << endl;

            JsonRequestPacketDeserializer::CommandRequest reqCom = JsonRequestPacketDeserializer::deserializeCommandRequest(req.d.c_str());
            my_ssh_session = this->m_clients.at(reqCom.accountId);
            rc = sshClient->exeCommand(my_ssh_session, reqCom, clientSocket);
            if (rc != SSH_OK)
            {
                fprintf(stderr, "Error: %s\n",
                    ssh_get_error(my_ssh_session));
                JsonResponsePacketSerializer::CommandResponse respCom{ ssh_get_error(my_ssh_session),reqCom.accountId };
                vector<unsigned char> respComVec = serializer->serializeCommandResponse(respCom, commandJson["fail"].dump().substr(1, commandJson["fail"].dump().size() - 2));
                this->messageQueue.push(string(respComVec.begin(), respComVec.end()));
                throw exception();
            }

            this->messageQueue.push(string(sshClient->currResp.begin(), sshClient->currResp.end()));

        }
        else if (req.type == requests["download"].dump()) {
            cout << "download" << endl;

            JsonRequestPacketDeserializer::DownloadRequest downCom = JsonRequestPacketDeserializer::deserializeDownloadRequest(req.d.c_str());
            my_ssh_session = this->m_clients.at(downCom.accountId);

            rc = sshClient->downloadFile(my_ssh_session, downCom, clientSocket);
            if (rc != SSH_OK)
            {
                fprintf(stderr, "Error: %s\n",
                    ssh_get_error(my_ssh_session));
                JsonResponsePacketSerializer::DownloadResponse respDown{ ssh_get_error(my_ssh_session),downCom.accountId,downCom.filePath,ssh_get_error(my_ssh_session) };
                vector<unsigned char> respComVec = serializer->serializeDownloadResponse(respDown, downloadJson["fail"].dump().substr(1, downloadJson["fail"].dump().size() - 2));
                this->messageQueue.push(string(respComVec.begin(), respComVec.end()));
                throw exception();
            }
            this->messageQueue.push(string(sshClient->currResp.begin(), sshClient->currResp.end()));

        }
        else if (req.type == requests["upload"].dump()) {
            cout << "upload" << endl;

            JsonRequestPacketDeserializer::UploadRequest upCom = JsonRequestPacketDeserializer::deserializeUploadRequest(req.d.c_str());
            my_ssh_session = this->m_clients.at(upCom.accountId);

            rc = sshClient->uploadFile(my_ssh_session, upCom, clientSocket);
            if (rc != SSH_OK)
            {
                fprintf(stderr, "Error: %s\n",
                    ssh_get_error(my_ssh_session));
                JsonResponsePacketSerializer::UploadResponse respUp{ ssh_get_error(my_ssh_session),upCom.accountId,upCom.localFilePath,upCom.remoteFilePath };
                vector<unsigned char> respComVec = serializer->serializeUploadResponse(respUp, uploadJson["fail"].dump().substr(1, uploadJson["fail"].dump().size() - 2));
                this->messageQueue.push(string(respComVec.begin(), respComVec.end()));
                throw exception();
            }
            this->messageQueue.push(string(sshClient->currResp.begin(), sshClient->currResp.end()));

        }
        else if (req.type == requests["getOSInfo"].dump()) {
            cout << "OS" << endl;

            JsonRequestPacketDeserializer::OSRequest OSCom = JsonRequestPacketDeserializer::deserializeOSRequest(req.d.c_str());
            my_ssh_session = this->m_clients.at(OSCom.accountId);

            rc = sshClient->getSystemOS(my_ssh_session, clientSocket, OSCom);
            if (rc != SSH_OK)
            {
                fprintf(stderr, "Error: %s\n",
                    ssh_get_error(my_ssh_session));
                JsonResponsePacketSerializer::OSResponse respOS{ ssh_get_error(my_ssh_session),OSCom.accountId };
                vector<unsigned char> respComVec = serializer->serializeOSResponse(respOS, OSJson["fail"].dump().substr(1, OSJson["fail"].dump().size() - 2));
                this->messageQueue.push(string(respComVec.begin(), respComVec.end()));
                throw exception();
            }
            this->messageQueue.push(string(sshClient->currResp.begin(), sshClient->currResp.end()));

        }
        else if (req.type == requests["getInteractiveShell"].dump()) {
            cout << "get" << endl;

            JsonRequestPacketDeserializer::GetShellRequest reqGet = JsonRequestPacketDeserializer::deserializeGetShellRequest(req.d.c_str());
            my_ssh_session = this->m_clients.at(reqGet.accountId);
            rc = sshClient->getInteractiveShell(my_ssh_session, reqGet);
            if (rc != SSH_OK)
            {
                fprintf(stderr, "Error: %s\n",
                    ssh_get_error(my_ssh_session));
                ssh_channel_close(sshClient->interactiveShell);
                ssh_channel_send_eof(sshClient->interactiveShell);
                ssh_channel_free(sshClient->interactiveShell);
                JsonResponsePacketSerializer::GetShellResponse respGet{ ssh_get_error(my_ssh_session),reqGet.accountId, reqGet.shellId, reqGet.username };
                vector<unsigned char> respComVec = serializer->serializeGetShellResponse(respGet, getInteractiveJson["fail"].dump().substr(1, getInteractiveJson["fail"].dump().size() - 2));
                this->messageQueue.push(string(respComVec.begin(), respComVec.end()));
                throw exception();
            }
            this->m_shells.insert(pair<string, ssh_channel>(reqGet.shellId, sshClient->interactiveShell));
            this->messageQueue.push(string(sshClient->currResp.begin(), sshClient->currResp.end()));

        }
        else if (req.type == requests["sendInteractiveShellCommand"].dump()) {
            //cout << "command shell" << endl;

            JsonRequestPacketDeserializer::CommandShellRequest reqComShell = JsonRequestPacketDeserializer::deserializeCommandShellRequest(req.d.c_str());
            my_ssh_session = this->m_clients.at(reqComShell.accountId);
            sshClient->interactiveShell = this->m_shells.at(reqComShell.shellId);
            rc = sshClient->commandShell(reqComShell, false);
            if (rc != SSH_OK)
            {
                fprintf(stderr, "Error: %s\n",
                    ssh_get_error(my_ssh_session));

                ssh_channel_close(sshClient->interactiveShell);
                ssh_channel_send_eof(sshClient->interactiveShell);
                ssh_channel_free(sshClient->interactiveShell);
                this->m_shells.erase(reqComShell.shellId);
                JsonResponsePacketSerializer::CommandShellResponse respGet{ ssh_get_error(my_ssh_session),reqComShell.accountId, reqComShell.shellId, reqComShell.username };
                vector<unsigned char> respComVec = serializer->serializeCommandShellResponse(respGet, commandInteractiveJson["fail"].dump().substr(1, commandInteractiveJson["fail"].dump().size() - 2));
                this->messageQueue.push(string(respComVec.begin(), respComVec.end()));
                throw exception();
            }
            this->messageQueue.push(string(sshClient->currResp.begin(), sshClient->currResp.end()));

        }
        else if (req.type == requests["closeInteractiveShell"].dump()) {
            cout << "exit shell" << endl;

            JsonRequestPacketDeserializer::CloseShellRequest reqCloseShell = JsonRequestPacketDeserializer::deserializeCloseShellRequest(req.d.c_str());
            my_ssh_session = this->m_clients.at(reqCloseShell.accountId);
            sshClient->interactiveShell = this->m_shells.at(reqCloseShell.shellId);
            JsonRequestPacketDeserializer::CommandShellRequest reqComShell{};
            reqComShell.accountId = reqCloseShell.accountId;
            reqComShell.shellId = reqCloseShell.shellId;
            reqComShell.username = reqCloseShell.username;
            reqComShell.command = "exit";
            rc = sshClient->commandShell(reqComShell, true);
            if (rc != SSH_OK)
            {
                fprintf(stderr, "Error: %s\n",
                    ssh_get_error(my_ssh_session));

                ssh_channel_close(sshClient->interactiveShell);
                ssh_channel_send_eof(sshClient->interactiveShell);
                ssh_channel_free(sshClient->interactiveShell);
                this->m_shells.erase(reqComShell.shellId);
                JsonResponsePacketSerializer::CloseShellResponse respCom{ ssh_get_error(my_ssh_session),reqComShell.accountId, reqComShell.shellId, reqComShell.username };
                vector<unsigned char> respComVec = serializer->serializeCloseShellResponse(respCom, closeInteractiveJson["fail"].dump().substr(1, closeInteractiveJson["fail"].dump().size() - 2));
                this->messageQueue.push(string(respComVec.begin(), respComVec.end()));
                throw exception();
            }
            ssh_channel_close(sshClient->interactiveShell);
            ssh_channel_send_eof(sshClient->interactiveShell);
            ssh_channel_free(sshClient->interactiveShell);
            this->m_shells.erase(reqComShell.shellId);
            this->messageQueue.push(string(sshClient->currResp.begin(), sshClient->currResp.end()));

        }
        else {
            throw exception();
        }
    }
    catch (const std::exception& e) {
        cout << "hey" << endl;
        cout << e.what() << endl;
    }
}

void Server::handleMessageQueue(SOCKET clientSocket)
{
    while (!this->isDisconnected) {
        if (!messageQueue.empty()) {
            auto currentMessage = messageQueue.front();
            messageQueue.pop();
            // Send message
            Helper::sendData(clientSocket, currentMessage);
        }
    }
}


void Server::acceptClient()
{

	// this accepts the client and create a specific socket from server to this client
	// the process will not continue until a client connects to the server
    this->isDisconnected = false;
    SOCKET client_socket = accept(_serverSocket, NULL, NULL);
	if (client_socket == INVALID_SOCKET)
		throw std::exception(__FUNCTION__);

	std::cout << "Client accepted. Server and client can speak" << std::endl;
	// the function that handle the conversation with the client
	clientHandler(client_socket);
}
//find os win: systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
//find os lin: cat /etc/os-release

void Server::clientHandler(SOCKET clientSocket)
{
    ssh_session my_ssh_session{};
    string msg;
    thread workerThread(&Server::handleMessageQueue, this, clientSocket);
    workerThread.detach();
    while (!this->isDisconnected) {
        try{
            msg = Helper::getStringPartFromSocket(clientSocket, 1024);
            thread t1(&Server::handleRequests, this, msg, clientSocket);
            t1.detach();
        }
        catch (const std::exception& e) {
            if (msg.size() == 0) this->isDisconnected = true;
        }
        
    }

    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    closesocket(clientSocket);
	//try
	//{
 //       ssh_session my_ssh_session{};
 //       string msg;
 //       thread workerThread(&Server::handleMessageQueue, this, clientSocket);
 //       workerThread.detach();
 //       while (!this->isDisconnected) {
 //           msg = Helper::getStringPartFromSocket(clientSocket, 1024);
 //           thread t1(&Server::handleRequests, this, msg, clientSocket);
 //           t1.detach();
 //       }

 //       ssh_disconnect(my_ssh_session);
 //       ssh_free(my_ssh_session);
	//	closesocket(clientSocket); 
	//}
	//catch (const std::exception& e)
	//{
 //       cout << "problem" << endl;
	//	//closesocket(clientSocket);
	//}
}

