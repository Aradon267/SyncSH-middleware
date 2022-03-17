#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <vector>
#include <bitset>
#include "json.hpp"
using nlohmann::json;
using namespace std;

class JsonResponsePacketSerializer
{
public:
	struct BaseResp
	{
		string type;
		string d;
	};
	struct LoginResponse
	{
		string message;
		string accountId;
	};
	struct CommandResponse
	{
		string message;
		string accountId;
		string sender;
		string command;
	};
	struct DownloadResponse
	{
		string message;
		string accountId;
		string filePath;
		string downloadedFileName;
	};
	struct UploadResponse
	{
		string message;
		string accountId;
		string localFilePath;
		string remoteFilePath;
	};
	struct OSResponse
	{
		string message;
		string accountId;
	};
	struct FPResponse
	{
		string message;
		string accountId;
	};
	struct GetShellResponse
	{
		string message;
		string accountId;
		string shellId;
		string username;
	};
	struct CommandShellResponse
	{
		string message;
		string accountId;
		string shellId;
		string username;
	};
	struct CloseShellResponse
	{
		string message;
		string accountId;
		string shellId;
		string username;
	};
	
	vector<unsigned char> serializeBase(BaseResp base);
	vector<unsigned char> serializeLoginResponse(LoginResponse log, string type);
	vector<unsigned char> serializeCommandResponse(CommandResponse log, string type);
	vector<unsigned char> serializeDownloadResponse(DownloadResponse log, string type);
	vector<unsigned char> serializeUploadResponse(UploadResponse log, string type);
	vector<unsigned char> serializeOSResponse(OSResponse log, string type);
	vector<unsigned char> serializeFPResponse(FPResponse log, string type);
	vector<unsigned char> serializeGetShellResponse(GetShellResponse log, string type);
	vector<unsigned char> serializeCommandShellResponse(CommandShellResponse log, string type);
	vector<unsigned char> serializeCloseShellResponse(CloseShellResponse log, string type);
	
	vector<unsigned char> buildMsg(json messageData);

};
