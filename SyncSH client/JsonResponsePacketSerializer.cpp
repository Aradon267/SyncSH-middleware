#include "JsonResponsePacketSerializer.h"

vector<unsigned char> JsonResponsePacketSerializer::serializeBase(BaseResp base)
{
    vector<unsigned char> buffer;
    json messageData;

    messageData["type"] = base.type;
    messageData["d"] = base.d;

    buffer = buildMsg(messageData);
    return buffer;

}

vector<unsigned char> JsonResponsePacketSerializer::serializeLoginResponse(LoginResponse log, string type)
{
    vector<unsigned char> buffer;
    vector<unsigned char> respBuffer;
    json messageData;

    messageData["message"] = log.message;
    messageData["accountId"] = log.accountId;

    buffer = buildMsg(messageData);
    BaseResp resp{ type, string(buffer.begin(),buffer.end())};
    respBuffer = serializeBase(resp);
    return respBuffer;

}

vector<unsigned char> JsonResponsePacketSerializer::serializeCommandResponse(CommandResponse log, string type)
{
    vector<unsigned char> buffer;
    vector<unsigned char> respBuffer;
    json messageData;

    messageData["message"] = log.message;
    messageData["accountId"] = log.accountId;
    messageData["sender"] = log.sender;
    messageData["command"] = log.command;

    buffer = buildMsg(messageData);
    BaseResp resp{ type, string(buffer.begin(),buffer.end()) };
    respBuffer = serializeBase(resp);
    return respBuffer;
}

vector<unsigned char> JsonResponsePacketSerializer::serializeDownloadResponse(DownloadResponse log, string type)
{
    vector<unsigned char> buffer;
    vector<unsigned char> respBuffer;
    json messageData;

    messageData["message"] = log.message;
    messageData["accountId"] = log.accountId;
    messageData["filePath"] = log.filePath;
    messageData["downloadedFileName"] = log.downloadedFileName;

    buffer = buildMsg(messageData);
    BaseResp resp{ type, string(buffer.begin(),buffer.end()) };
    respBuffer = serializeBase(resp);
    return respBuffer;
}

vector<unsigned char> JsonResponsePacketSerializer::serializeUploadResponse(UploadResponse log, string type)
{
    vector<unsigned char> buffer;
    vector<unsigned char> respBuffer;
    json messageData;

    messageData["message"] = log.message;
    messageData["accountId"] = log.accountId;
    messageData["localFilePath"] = log.localFilePath;
    messageData["remoteFilePath"] = log.remoteFilePath;

    buffer = buildMsg(messageData);
    BaseResp resp{ type, string(buffer.begin(),buffer.end()) };
    respBuffer = serializeBase(resp);
    return respBuffer;
}

vector<unsigned char> JsonResponsePacketSerializer::serializeOSResponse(OSResponse log, string type)
{
    vector<unsigned char> buffer;
    vector<unsigned char> respBuffer;
    json messageData;

    messageData["message"] = log.message;
    messageData["accountId"] = log.accountId;

    buffer = buildMsg(messageData);
    BaseResp resp{ type, string(buffer.begin(),buffer.end()) };
    respBuffer = serializeBase(resp);
    return respBuffer;
}

vector<unsigned char> JsonResponsePacketSerializer::serializeFPResponse(FPResponse log, string type)
{
    vector<unsigned char> buffer;
    vector<unsigned char> respBuffer;
    json messageData;

    messageData["message"] = log.message;
    messageData["accountId"] = log.accountId;

    buffer = buildMsg(messageData);
    BaseResp resp{ type, string(buffer.begin(),buffer.end()) };
    respBuffer = serializeBase(resp);
    return respBuffer;
}

vector<unsigned char> JsonResponsePacketSerializer::serializeGetShellResponse(GetShellResponse log, string type)
{
    vector<unsigned char> buffer;
    vector<unsigned char> respBuffer;
    json messageData;

    messageData["message"] = log.message;
    messageData["accountId"] = log.accountId;
    messageData["shellId"] = log.shellId;
    messageData["username"] = log.username;

    buffer = buildMsg(messageData);
    BaseResp resp{ type, string(buffer.begin(),buffer.end()) };
    respBuffer = serializeBase(resp);
    return respBuffer;
}

vector<unsigned char> JsonResponsePacketSerializer::serializeCommandShellResponse(CommandShellResponse log, string type)
{
    vector<unsigned char> buffer;
    vector<unsigned char> respBuffer;
    json messageData;

    messageData["message"] = log.message;
    messageData["accountId"] = log.accountId;
    messageData["shellId"] = log.shellId;
    messageData["username"] = log.username;

    buffer = buildMsg(messageData);
    BaseResp resp{ type, string(buffer.begin(),buffer.end()) };
    respBuffer = serializeBase(resp);
    return respBuffer;
}

vector<unsigned char> JsonResponsePacketSerializer::serializeCloseShellResponse(CloseShellResponse log, string type)
{
    vector<unsigned char> buffer;
    vector<unsigned char> respBuffer;
    json messageData;

    messageData["accountId"] = log.accountId;
    messageData["shellId"] = log.shellId;
    messageData["username"] = log.username;
    messageData["message"] = log.message;

    buffer = buildMsg(messageData);
    BaseResp resp{ type, string(buffer.begin(),buffer.end()) };
    respBuffer = serializeBase(resp);
    return respBuffer;
}

vector<unsigned char> JsonResponsePacketSerializer::buildMsg(json messageData)
{
    vector<unsigned char> resp;
    int len = 0;
    string temp;
    unsigned char* msgBytes;
    temp = messageData.dump();
    len = temp.length();
    msgBytes = new unsigned char[temp.length() + 1];
    strcpy((char*)msgBytes, temp.c_str());



    for (int i = 0; i < len; i++)
    {
        resp.push_back(msgBytes[i]);
    }

    return resp;

}
