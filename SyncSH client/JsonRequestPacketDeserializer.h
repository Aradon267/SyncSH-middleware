#pragma once

#include <iostream>
#include <vector>
#include <bitset>
#include <string>
#include "json.hpp"
using json = nlohmann::json;
using namespace std;


class JsonRequestPacketDeserializer
{
public:

	typedef struct Base
	{
		string type;
		string d;
	}Base;

	typedef struct LoginRequest
	{
		string accountId;
		string serverIP;
		string serverPort;
		string accountName;
		string accountPassword;
	}LoginRequest;

	typedef struct CommandRequest
	{
		string accountId;
		string command;
		string sender;
	}CommandRequest;

	typedef struct DownloadRequest
	{
		string accountId;
		string filePath;
	}DownloadRequest;

	typedef struct UploadRequest
	{
		string accountId;
		string localFilePath;
		string remoteFilePath;
	}UploadRequest;

	typedef struct OSRequest
	{
		string accountId;
	}OSRequest;

	typedef struct FPRequest
	{
		string accountId;
		string serverIP;
		string serverPort;
	}FPRequest;

	typedef struct GetShellRequest
	{
		string accountId;
		string shellId;
		string username;
	}GetShellRequest;

	typedef struct CommandShellRequest
	{
		string accountId;
		string shellId;
		string username;
		string command;
	}CommandShellRequest;

	typedef struct CloseShellRequest
	{
		string accountId;
		string shellId;
		string username;
	}CloseShellRequest;

	static Base deserializeBase(const char* log);
	static LoginRequest deserializeLoginRequest(const char* log);
	static CommandRequest deserializeCommandRequest(const char* log);
	static DownloadRequest deserializeDownloadRequest(const char* log);
	static UploadRequest deserializeUploadRequest(const char* log);
	static OSRequest deserializeOSRequest(const char* log);
	static FPRequest deserializeFPRequest(const char* log);
	static GetShellRequest deserializeGetShellRequest(const char* log);
	static CommandShellRequest deserializeCommandShellRequest(const char* log);
	static CloseShellRequest deserializeCloseShellRequest(const char* log);

};

