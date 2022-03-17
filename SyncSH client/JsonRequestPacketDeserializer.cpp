#include "JsonRequestPacketDeserializer.h"

JsonRequestPacketDeserializer::Base JsonRequestPacketDeserializer::deserializeBase(const char* log)
{
    Base req;
    const string output(log);
    string type = "";
    string d = "";
	try {
		auto j = json::parse(output);
		type = j["type"].dump();
		d = j["d"].dump();
	}
	catch (const std::exception& e) {
		cout << e.what() << endl;
	}
	req.type = type;
	req.d = d;
	return req;

}

JsonRequestPacketDeserializer::LoginRequest JsonRequestPacketDeserializer::deserializeLoginRequest(const char* log)
{
	LoginRequest req;
	const string output(log);
	string accountId;
	string serverIP;
	string serverPort;
	string accountName;
	string accountPassword;
	//parse string in json format to json object
	auto j = json::parse(output);
	accountId = j["accountId"].dump();
	serverIP = j["serverIP"].dump();
	serverPort = j["serverPort"].dump();
	accountName = j["accountName"].dump();
	accountPassword = j["accountPassword"].dump();

	req.accountId = accountId.substr(1, accountId.size() - 2);
	req.serverIP = serverIP.substr(1, serverIP.size() - 2);
	//req.serverPort = serverPort.substr(1, serverPort.size() - 2);
	req.serverPort = serverPort;
	req.accountName = accountName.substr(1, accountName.size() - 2);
	req.accountPassword = accountPassword.substr(1, accountPassword.size() - 2);


	return req;

}

JsonRequestPacketDeserializer::CommandRequest JsonRequestPacketDeserializer::deserializeCommandRequest(const char* log)
{
	CommandRequest req;
	const string output(log);
	string accountId;
	string command;
	string sender;

	//parse string in json format to json object
	auto j = json::parse(output);
	accountId = j["accountId"].dump();
	command = j["command"].dump();
	sender = j["sender"].dump();


	req.accountId = accountId.substr(1, accountId.size() - 2);
	req.command = command.substr(1, command.size() - 2);
	req.sender = sender.substr(1, sender.size() - 2);

	

	return req;
}

JsonRequestPacketDeserializer::DownloadRequest JsonRequestPacketDeserializer::deserializeDownloadRequest(const char* log)
{
	DownloadRequest req;
	const string output(log);
	string accountId;
	string filePath;

	//parse string in json format to json object
	auto j = json::parse(output);
	accountId = j["accountId"].dump();
	filePath = j["filePath"].dump();


	req.accountId = accountId.substr(1, accountId.size() - 2);
	req.filePath = filePath.substr(1, filePath.size() - 2);


	return req;
}

JsonRequestPacketDeserializer::UploadRequest JsonRequestPacketDeserializer::deserializeUploadRequest(const char* log)
{
	UploadRequest req;
	const string output(log);
	string accountId;
	string local;
	string remote;

	//parse string in json format to json object
	auto j = json::parse(output);
	accountId = j["accountId"].dump();
	local = j["localFilePath"].dump();
	remote = j["remoteFilePath"].dump();


	req.accountId = accountId.substr(1, accountId.size() - 2);
	req.localFilePath = local.substr(1, local.size() - 2);
	req.remoteFilePath = remote.substr(1, remote.size() - 2);

	

	return req;
}

JsonRequestPacketDeserializer::OSRequest JsonRequestPacketDeserializer::deserializeOSRequest(const char* log)
{
	OSRequest req;
	const string output(log);
	string accountId;

	auto j = json::parse(output);
	accountId = j["accountId"].dump();

	req.accountId = accountId.substr(1, accountId.size() - 2);


	return req;
}

JsonRequestPacketDeserializer::FPRequest JsonRequestPacketDeserializer::deserializeFPRequest(const char* log)
{
	FPRequest req;
	const string output(log);
	string accountId;
	string serverIP;
	string serverPort;

	auto j = json::parse(output);
	accountId = j["accountId"].dump();
	serverIP = j["serverIP"].dump();
	serverPort = j["serverPort"].dump();

	req.accountId = accountId.substr(1, accountId.size() - 2);
	req.serverIP = serverIP.substr(1, serverIP.size() - 2);
	req.serverPort = serverPort;
	//req.serverPort = serverPort.substr(1, serverPort.size() - 2);

	return req;
}

JsonRequestPacketDeserializer::GetShellRequest JsonRequestPacketDeserializer::deserializeGetShellRequest(const char* log)
{
	GetShellRequest req;
	const string output(log);
	string accountId;
	string shellId;
	string username;

	auto j = json::parse(output);
	accountId = j["accountId"].dump();
	shellId = j["shellId"].dump();
	username = j["username"].dump();

	req.accountId = accountId.substr(1, accountId.size() - 2);
	req.shellId = shellId.substr(1, shellId.size() - 2);
	req.username = username.substr(1, username.size() - 2);

	return req;
}

JsonRequestPacketDeserializer::CommandShellRequest JsonRequestPacketDeserializer::deserializeCommandShellRequest(const char* log)
{
	CommandShellRequest req;
	const string output(log);
	string accountId;
	string shellId;
	string username;
	string command;

	auto j = json::parse(output);
	accountId = j["accountId"].dump();
	shellId = j["shellId"].dump();
	username = j["username"].dump();
	command = j["command"].dump();

	req.accountId = accountId.substr(1, accountId.size() - 2);
	req.shellId = shellId.substr(1, shellId.size() - 2);
	req.username = username.substr(1, username.size() - 2);
	req.command = command.substr(1, command.size() - 2);

	return req;
}

JsonRequestPacketDeserializer::CloseShellRequest JsonRequestPacketDeserializer::deserializeCloseShellRequest(const char* log)
{
	CloseShellRequest req;
	const string output(log);
	string accountId;
	string shellId;
	string username;

	auto j = json::parse(output);
	accountId = j["accountId"].dump();
	shellId = j["shellId"].dump();
	username = j["username"].dump();

	req.accountId = accountId.substr(1, accountId.size() - 2);
	req.shellId = shellId.substr(1, shellId.size() - 2);
	req.username = username.substr(1, username.size() - 2);

	return req;
}
