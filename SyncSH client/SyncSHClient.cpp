#include "SyncSHClient.h"

SyncSHClient::SyncSHClient() {
    JsonResponsePacketSerializer* serializer = new JsonResponsePacketSerializer();
    this->serializer = serializer;
}


int SyncSHClient::exeCommand(ssh_session session, JsonRequestPacketDeserializer::CommandRequest command, SOCKET sock)
{
    ssh_channel channel;
    int rc;

    channel = ssh_channel_new(session);
    if (channel == NULL) return SSH_ERROR;

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK)
    {
        ssh_channel_free(channel);
        return rc;
    }

    rc = ssh_channel_request_exec(channel, command.command.c_str());
    if (rc != SSH_OK)
    {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return rc;
    }
    char buffer[256];
    int nbytes;
    string resp;
    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    if (nbytes == 0) {
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 1);
        while (nbytes > 0)
        {
            if (fwrite(buffer, 1, nbytes, stdout) != nbytes)
            {
                ssh_channel_close(channel);
                ssh_channel_free(channel);
                return SSH_ERROR;
            }
            for (int i = 0; i < nbytes; i++) {
                resp = resp + buffer[i];
            }
            
            nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 1);
        }
        JsonResponsePacketSerializer::CommandResponse respCommand{ resp, command.accountId,command.sender,command.command };
        vector<unsigned char> respLog = serializer->serializeCommandResponse(respCommand, "sendCommandSuccess");
        this->currResp = respLog;

        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);

        return SSH_OK;
    }
    while (nbytes > 0)
    {
        if (fwrite(buffer, 1, nbytes, stdout) != nbytes)
        {
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            return SSH_ERROR;
        }
        for (int i = 0; i < nbytes; i++) {
            resp = resp + buffer[i];
        }
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    }

    if (nbytes < 0)
    {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return SSH_ERROR;
    }
    JsonResponsePacketSerializer::CommandResponse respCommand{ resp, command.accountId,command.sender,command.command };
    vector<unsigned char> respLog = serializer->serializeCommandResponse(respCommand, "sendCommandSuccess");
    this->currResp = respLog;
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);

    return SSH_OK;
}

int SyncSHClient::shell_session(ssh_session session)
{
    ssh_channel channel;
    int rc;

    channel = ssh_channel_new(session);
    if (channel == NULL)
        return SSH_ERROR;

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK)
    {
        ssh_channel_free(channel);
        return rc;
    }


    rc = ssh_channel_request_pty(channel);
    if (rc != SSH_OK) return rc;

    rc = ssh_channel_change_pty_size(channel, 80, 24);
    if (rc != SSH_OK) return rc;

    rc = ssh_channel_request_shell(channel);
    if (rc != SSH_OK) return rc;


    std::string commandString = "";
    char buffer[512];
    int bytesRead, bytesWrittenToConsole;

    while (ssh_channel_is_open(channel) && !ssh_channel_is_eof(channel)) {
        // _nonblocking
        bytesRead = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer), 0);
        if (bytesRead < 0) {
            rc = SSH_ERROR;
            break;
        }
        if (bytesRead > 0) {
            bytesWrittenToConsole = fwrite(buffer, 1, bytesRead, stdout);
            //send
        }
        else {
            break;
        }
    }
    if (rc != SSH_OK)
    {
        ssh_channel_close(channel);
        ssh_channel_send_eof(channel);
        ssh_channel_free(channel);
        return rc;
    }
    ssh_channel_close(channel);
    ssh_channel_send_eof(channel);
    ssh_channel_free(channel);

    return SSH_OK;
}

int SyncSHClient::uploadFile(ssh_session session, JsonRequestPacketDeserializer::UploadRequest upload, SOCKET sock)
{
    sftp_session sftp;
    int rc;
    sftp = sftp_new(session);
    if (sftp == NULL)
    {
        fprintf(stderr, "Error allocating SFTP session: %s\n",
            ssh_get_error(session));
        return SSH_ERROR;
    }
    rc = sftp_init(sftp);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "Error initializing SFTP session: %s.\n",
            sftp_get_error(sftp));
        sftp_free(sftp);
        return rc;
    }
    // Set variable for the communication
    char buffer[256];
    unsigned int nbytes;
    int nwritten;
    //create a file to send by SFTP
    sftp_file file;
    int access_type = O_WRONLY | O_CREAT | O_TRUNC;
    string src = "";
    string dest = "";

    //Open a SFTP session
    sftp = sftp_new(session);
    if (sftp == NULL)
    {
        fprintf(stderr, "Error allocating SFTP session: %s\n",
            ssh_get_error(session));
        return SSH_ERROR;
    }
    // Initialize the SFTP session
    rc = sftp_init(sftp);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "Error initializing SFTP session: %s.\n",
            sftp_get_error(sftp));
        sftp_free(sftp);
        return rc;
    }

    src = upload.localFilePath;
    dest = upload.remoteFilePath;

    //Open the file into the remote side
    file = sftp_open(sftp, dest.c_str(), access_type, 1);
    if (file == NULL)
    {
        fprintf(stderr, "Can't open file for writing: %s\n", ssh_get_error(session));
        return SSH_ERROR;
    }

    //Write the file created with what's into the buffer
    ifstream fin(src.c_str(), ios::binary);
    if (fin) {
        fin.seekg(0, ios::end);
        ios::pos_type bufsize = fin.tellg();   // get file size in bytes
        fin.seekg(0);                          // rewind to beginning of file

        vector<char> buf(bufsize);        // allocate buffer
        fin.read(buf.data(), bufsize);         // read file contents into buffer

        nwritten = sftp_write(file, buf.data(), bufsize); // write buffer to remote file
        if (nwritten != bufsize)
        {
            fprintf(stderr, "Can't write data to file: %s\n",
                ssh_get_error(session));
            sftp_close(file);
            return SSH_ERROR;
        }
    }
    JsonResponsePacketSerializer::UploadResponse respUpload{ "successfully uploaded the file to the server", upload.accountId,upload.localFilePath,upload.remoteFilePath };
    vector<unsigned char> respLog = serializer->serializeUploadResponse(respUpload, "uploadSuccess");
    this->currResp = respLog;
    return SSH_OK;
}

int SyncSHClient::downloadFile(ssh_session session, JsonRequestPacketDeserializer::DownloadRequest download, SOCKET sock)
{
    char buffer[16384];
    sftp_session sftp;
    int rc;
    string src = "";
    string dest = "";
    string pathFile = "";
    char destTemp[40];
    int access_type = O_RDONLY;
    unsigned int nbytes;

    sftp = sftp_new(session);
    if (sftp == NULL)
    {
        fprintf(stderr, "Error allocating SFTP session: %s\n",
            ssh_get_error(session));
        return SSH_ERROR;
    }
    rc = sftp_init(sftp);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "Error initializing SFTP session: %s.\n",
            sftp_get_error(sftp));
        sftp_free(sftp);
        return rc;
    }


    src = download.filePath;
    //string suffix;
    //suffix = fs::path(src).extension().string();
    /*const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv";
    int stringLength = sizeof(alphanum) - 1;
    srand(time(NULL));*/
    sole::uuid u1 = sole::uuid1();
    dest.append("c:\\Users\\Arad Donenfeld\\Desktop\\downloaded_files\\");
    /*for (int i = 0; i < 10; ++i)
    {
        pathFile += alphanum[rand() % stringLength];
    }*/
    //pathFile += suffix;
    dest = dest + u1.str();


    sftp_file file = sftp_open(sftp, src.c_str(), access_type, 0);
    if (file == NULL)
    {
        fprintf(stderr, "Can't open file for writing: %s\n", ssh_get_error(session));
        return SSH_ERROR;
    }

    ofstream fin(dest.c_str(), ios::binary | ios::in | std::ofstream::out | std::ofstream::app);
    if (fin) {
        for (;;)
        {
            nbytes = sftp_read(file, buffer, sizeof(buffer));
            if (nbytes == 0)
            {
                break; // EOF
            }
            else if (nbytes < 0)
            {
                fprintf(stderr, "Error while reading file: %s\n", ssh_get_error(session));
                sftp_close(file);
                return SSH_ERROR;
            }

            fin.write(buffer, nbytes);
            if (!fin)
            {
                fprintf(stderr, "Error writing");
                sftp_close(file);
                return SSH_ERROR;
            }
        }
    }
    fin.close();
    if (!fin)
    {
        fprintf(stderr, "Error writing");
        sftp_close(file);
        return SSH_ERROR;
    }
    JsonResponsePacketSerializer::DownloadResponse respDownload{ "successfully downloaded the file from the server", download.accountId,download.filePath,dest };
    vector<unsigned char> respLog = serializer->serializeDownloadResponse(respDownload, "downloadSuccess");
    this->currResp = respLog;
    return SSH_OK;
}

int SyncSHClient::verify_knownhost(ssh_session session, SOCKET sock, JsonRequestPacketDeserializer::FPRequest FP)
{
    unsigned char* hash = NULL;
    ssh_key srv_pubkey = NULL;
    size_t hlen;
    char* hexa;
    int rc;

    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if (rc < 0) {
        return -1;
    }

    rc = ssh_get_publickey_hash(srv_pubkey,
        SSH_PUBLICKEY_HASH_SHA1,
        &hash,
        &hlen);
    ssh_key_free(srv_pubkey);
    if (rc < 0) {
        return -1;
    }

    hexa = ssh_get_hexa(hash, hlen);

    JsonResponsePacketSerializer::FPResponse respFP{ hexa, FP.accountId};
    vector<unsigned char> respLog = serializer->serializeFPResponse(respFP, "sshCollectFingerprintSuccess");
    this->currResp = respLog;
    ssh_string_free_char(hexa);
    ssh_clean_pubkey_hash(&hash);
    return 0;
}

int SyncSHClient::getSystemOS(ssh_session session, SOCKET sock, JsonRequestPacketDeserializer::OSRequest OS)
{
    ssh_channel channel;
    int rc;

    channel = ssh_channel_new(session);
    if (channel == NULL) return SSH_ERROR;

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK)
    {
        ssh_channel_free(channel);
        return rc;
    }

    rc = ssh_channel_request_exec(channel, "systeminfo | findstr /B /C:\"OS Name\"");
    if (rc != SSH_OK)
    {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return rc;
    }
    char buffer[256];
    int nbytes;
    string resp;
    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    if (nbytes == 0) {
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 1);
        while (nbytes > 0)
        {
            if (fwrite(buffer, 1, nbytes, stdout) != nbytes)
            {
                ssh_channel_close(channel);
                ssh_channel_free(channel);
                return SSH_ERROR;
            }
            for (int i = 0; i < nbytes; i++) {
                resp = resp + buffer[i];
            }

            nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 1);
        }

        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);

        rc = getSystemOSNotWin(session, sock, OS);

        return rc;
    }
    while (nbytes > 0)
    {
        if (fwrite(buffer, 1, nbytes, stdout) != nbytes)
        {
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            return SSH_ERROR;
        }
        for (int i = 0; i < nbytes; i++) {
            resp = resp + buffer[i];
        }
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    }

    if (nbytes < 0)
    {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return SSH_ERROR;
    }
    auto osName = resp.substr(string("OS Name:").size());
    Helper::trim(osName);
    JsonResponsePacketSerializer::OSResponse respOS{ osName, OS.accountId};
    vector<unsigned char> respLog = serializer->serializeOSResponse(respOS, "getOSInfoSuccess");
    this->currResp = respLog;
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);

    return SSH_OK;
}

int SyncSHClient::getSystemOSNotWin(ssh_session session, SOCKET sock, JsonRequestPacketDeserializer::OSRequest OS)
{
    ssh_channel channel;
    int rc;

    channel = ssh_channel_new(session);
    if (channel == NULL) return SSH_ERROR;

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK)
    {
        ssh_channel_free(channel);
        return rc;
    }

    rc = ssh_channel_request_exec(channel, "grep '^NAME' /etc/os-release");
    if (rc != SSH_OK)
    {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return rc;
    }
    char buffer[256];
    int nbytes;
    string resp;
    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    if (nbytes == 0) {
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 1);
        while (nbytes > 0)
        {
            if (fwrite(buffer, 1, nbytes, stdout) != nbytes)
            {
                ssh_channel_close(channel);
                ssh_channel_free(channel);
                return SSH_ERROR;
            }
            for (int i = 0; i < nbytes; i++) {
                resp = resp + buffer[i];
            }

            nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 1);
        }
        JsonResponsePacketSerializer::OSResponse respOS{ "Unknown", OS.accountId };
        vector<unsigned char> respLog = serializer->serializeOSResponse(respOS, "getOSInfoSuccess");
        this->currResp = respLog;

        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);

        return SSH_OK;
    }
    while (nbytes > 0)
    {
        if (fwrite(buffer, 1, nbytes, stdout) != nbytes)
        {
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            return SSH_ERROR;
        }
        for (int i = 0; i < nbytes; i++) {
            resp = resp + buffer[i];
        }
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        std::this_thread::sleep_for(std::chrono::microseconds(50000));

    }

    if (nbytes < 0)
    {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return SSH_ERROR;
    }
    auto osName = resp.substr(resp.find_first_of("=")+1);
    JsonResponsePacketSerializer::OSResponse respOS{ osName, OS.accountId };
    vector<unsigned char> respLog = serializer->serializeOSResponse(respOS, "getOSInfoSuccess");
    this->currResp = respLog;
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);

    return SSH_OK;
}

int SyncSHClient::getInteractiveShell(ssh_session session, JsonRequestPacketDeserializer::GetShellRequest shell)
{
    ssh_channel channel;
    int rc;

    channel = ssh_channel_new(session);
    if (channel == NULL)
        return SSH_ERROR;

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK)
    {
        ssh_channel_free(channel);
        return rc;
    }


    rc = ssh_channel_request_pty(channel);
    if (rc != SSH_OK) return rc;

    rc = ssh_channel_change_pty_size(channel, 80, 24);
    if (rc != SSH_OK) return rc;

    rc = ssh_channel_request_shell(channel);
    if (rc != SSH_OK) return rc;

    this->interactiveShell = channel;

    std::string resp = "";
    char buffer[512];
    int bytesRead, bytesWrittenToConsole;

    while (ssh_channel_is_open(channel) && !ssh_channel_is_eof(channel)) {
        // _nonblocking
        bytesRead = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer), 0);
        if (bytesRead < 0) {
            rc = SSH_ERROR;
            break;
        }
        if (bytesRead > 0) {
            bytesWrittenToConsole = fwrite(buffer, 1, bytesRead, stdout);
            //send
            for (int i = 0; i < bytesWrittenToConsole; i++) {
                resp = resp + buffer[i];
            }
            std::this_thread::sleep_for(std::chrono::microseconds(50000));
        }
        else {
            break;
        }
    }
    if (rc != SSH_OK)
    {
        return rc;
    }
    JsonResponsePacketSerializer::GetShellResponse respGetShelld{ resp, shell.accountId,shell.shellId,shell.username };
    vector<unsigned char> respLog = serializer->serializeGetShellResponse(respGetShelld, "sshGetInteractiveShellSuccess");
    this->currResp = respLog;
    return SSH_OK;
}

int SyncSHClient::commandShell(JsonRequestPacketDeserializer::CommandShellRequest shell, bool close)
{
    int rc = 0;

    rc = ssh_channel_write(this->interactiveShell, shell.command.c_str(), shell.command.length());
    if (rc == SSH_ERROR) {
        return rc;
    }
    rc = ssh_channel_write(this->interactiveShell, "\n", 1);
    if (rc == SSH_ERROR) {
        return rc;
    }
    std::string resp = "";
    char buffer[512];
    int bytesRead, bytesWrittenToConsole;

    while (ssh_channel_is_open(this->interactiveShell) && !ssh_channel_is_eof(this->interactiveShell)) {
        // _nonblocking
        bytesRead = ssh_channel_read_nonblocking(this->interactiveShell, buffer, sizeof(buffer), 0);
        if (bytesRead < 0) {
            rc = SSH_ERROR;
            break;
        }
        if (bytesRead > 0) {
            bytesWrittenToConsole = fwrite(buffer, 1, bytesRead, stdout);
            //send
            for (int i = 0; i < bytesWrittenToConsole; i++) {
                resp = resp + buffer[i];
            }
        }
        else {
            break;
        }
    }
    if (rc == SSH_ERROR)
    {
        return rc;
    }
    if (!close) {
        JsonResponsePacketSerializer::CommandShellResponse respCommandShell{ resp, shell.accountId,shell.shellId,shell.username };
        vector<unsigned char> respLog = serializer->serializeCommandShellResponse(respCommandShell, "sshSendInteractiveShellSuccess");
        this->currResp = respLog;
    }
    else {
        JsonResponsePacketSerializer::CloseShellResponse respCloseShell{"Good", shell.accountId,shell.shellId,shell.username};
        vector<unsigned char> respLog = serializer->serializeCloseShellResponse(respCloseShell, "sshCloseInteractiveShellSuccess");
        this->currResp = respLog;
    }
    return SSH_OK;
}

