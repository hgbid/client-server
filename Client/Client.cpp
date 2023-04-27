// Client.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "Client.h"
using namespace std;
using namespace CryptoPP;

WSA wsa;

string getClntName() {
    fstream tr_file("transfer.info");
    string adrss;
    string clnt_name = "";

    if (!tr_file.is_open()) {
        cout << "Error: File 'transfer.info' not found" << endl;
        return 0;
    }
    try {
        getline(tr_file, adrss);
        getline(tr_file, clnt_name);
        tr_file.close();
    }
    catch (...) {
        cout << "Error in file 'transfer' format" << endl;
    }
    return clnt_name;
}


int makeMeFile(string clnt_name, string cID, keys clinet_keys) {
    //make 'me.info' file
    ofstream me_file;
    me_file.open("me.info");
    me_file << clnt_name << endl; // client name
    me_file << cID << endl; //client ID
    me_file << clinet_keys.privKeyBase64 << endl; //private key
    me_file.close();
    cout << "- Client data saved into me.info file" << endl;

    return 0;
}



int registation(SOCKET s, string& AESKey) {
    string rgstr_rqst, cID;
    string clnt_name = getClntName();
    char server_ans[1025] = { 0 };

    //send registation request
    string str_req = makeRequest("", C_REGISTER_CODE, clnt_name);
    cout << "- Sending registation request..." << endl;
    const char* rqst = str_req.data();
    send(s, rqst, strlen(rqst), 0);

    //get cID
    recv(s, server_ans, 1024, 0);
    cout << "\n@ Received message: " << server_ans << endl;
    if (sliceCharArr(server_ans, CODE_INDEX, SIZE_INDEX) == S_GENERAL_ERROR) {
        cout << "- Server responded with an error" << endl;
        return 1;
    }
    string ans_code = sliceCharArr(server_ans, CODE_INDEX, SIZE_INDEX);
    if (ans_code == S_REGISTER_SUCC_CODE) {
        cout << "- Register succied" << endl;
        cID = sliceCharArr(server_ans, 7, strlen(server_ans));

        keys cKeys = generateKeys();
        makeMeFile(clnt_name, cID, cKeys);

        // send public key
        str_req = makeRequest(cID, C_SEND_PUBL_KEY_CODE, cKeys.pubKeyBase64.data());
        rqst = str_req.data();
        cout << "- Sending public key..." << endl;
        send(s, rqst, strlen(rqst), 0);

        // get AES encrypt key
        recv(s, server_ans, 1024, 0);
        cout << "\n@ Received message: " << arrengeMassage(server_ans) << endl;
        if (sliceCharArr(server_ans, CODE_INDEX, SIZE_INDEX) == S_GENERAL_ERROR) {
            cout << "- Server responded with an error" << endl;
            return 1;
        }
        string enAESKey = sliceCharArr(server_ans, 8, strlen(server_ans));
        AESKey = decryptAESKey(enAESKey, cKeys);         // decrypt AES key by private key
        string decoded;
        StringSource ss(AESKey, true,
            new Base64Encoder(new StringSink(decoded))); // Encode to Base64
        cout << "- AES key Decrypted" << endl;
    }
    else if (ans_code == S_REGISTER_FAIL_CODE) {
        cout << "- Register failed" << endl;
        return 1;
    }
    return 0;
}


int sendEncryptFileCont(SOCKET sock, string enMassagge) {
    const int BUFFER_SIZE = 1024;
    char buffer[BUFFER_SIZE];
    int bytes_sent = 0;
    while (bytes_sent < enMassagge.length()) {
        int bytes_to_send = min(BUFFER_SIZE, enMassagge.length() - bytes_sent);
        string toSend = enMassagge.substr(bytes_sent, bytes_to_send);

        int bytes_sent_now = send(sock, toSend.data(), toSend.length(), 0);
        if (bytes_sent_now == -1) {
            cerr << "Send error" << endl;
            return 1;
        }
        bytes_sent += bytes_sent_now;
    }
    return 0;
}
int crc_incorrect_end(SOCKET sock, string filename) {
    string request = makeRequest(getCID(), C_CRC_ERROR_END_CODE, filename);
    if (send(sock, request.data(), request.length(), 0) == -1) {
        cerr << "Send error" << endl;
        return 1;
    }
    char server_ans[1025] = { 0 };
    recv(sock, server_ans, 1024, 0);
    cout << "\n@ Received message: " << arrengeMassage(server_ans) << endl;
    if (!(sliceCharArr(server_ans, CODE_INDEX, SIZE_INDEX) == S_OK_END)) {
        return 1;
    }
    cout << "- Sever confirmed" << endl;
    return 0;
}

int sendfile(SOCKET sock, string AESKey, int attempts) {
    string filename; getFileName(filename);
    if (attempts == 3)
        return crc_incorrect_end(sock, filename);

    string enMassagge, paylaod, request;
    encryptFile(AESKey, filename, enMassagge);

    char filesize[256] = "";
    snprintf(filesize, sizeof filesize, "%zu", enMassagge.size());

    paylaod = paddMassage(FILESIZE_SIZE, string(filesize));
    paylaod += paddMassage(FILENAME_SIZE, filename);
    if (attempts > 0) {
        cout << "- Sending the file again" << endl;
        request = makeRequest(getCID(), C_CRC_ERROR_SA_CODE, filename);
    }
    else
        request = makeRequest(getCID(), C_SEND_FILE_CODE, paylaod);
    if (send(sock, request.data(), request.length(), 0) == -1) {
        cerr << "Send error" << endl;
        return 1;
    }

    cout << "- Sending encrypt file: " << filename << "..." << endl;
    sendEncryptFileCont(sock, enMassagge);

    return 0;
}

int checkCrc(SOCKET s, int& crc_ok) {
    char server_ans[1025] = { 0 };
    recv(s, server_ans, 1024, 0);
    cout << "\n@ Received message: " << arrengeMassage(server_ans) << endl;

    if (sliceCharArr(server_ans, CODE_INDEX, SIZE_INDEX) == S_GENERAL_ERROR) {
        cout << "- Server responded with an error" << endl;
        return 1;
    }

    string filename_client; getFileName(filename_client);

    string str = server_ans;
    str = str.substr(8, 255);
    str.erase(remove_if(str.begin(), str.end(), isspace), str.end());
    string filename_server = str;
    if (filename_server != filename_client) {
        cout << "- Note: filename server: " << filename_server << ". filename client: " << filename_client << endl;
    }
    string client_crc = crc32(filename_client);
    str = server_ans;
    str = str.substr((255 + 8), str.length());
    str.erase(remove_if(str.begin(), str.end(), isspace), str.end());
    string server_crc = str;
    cout << "- Client CRC:" << client_crc << ". Server CRC:" << server_crc;
    if (server_crc.compare(client_crc) == 0) {
        cout << "-> CRC OK" << endl;
        crc_ok = 1;
        cout << "- Sending a confirmation..." << endl;
        string request = makeRequest(getCID(), C_CRC_OK_CODE, filename_client);
        if (send(s, request.data(), request.length(), 0) == -1) {
            cerr << "Send error" << endl;
            return 1;
        }
    }
    else {
        cout << "-> Error: CRC incorrect" << endl;
    }

    return 0;
}

int reconnect(SOCKET s, string& aes_key) {
    cout << "- Sending reconnect request..." << endl;
    string request = makeRequest(getCID(), C_RECONNECT_CODE, getClientName());
    if (send(s, request.data(), request.length(), 0) == -1) {
        cerr << "Send error" << endl;
        return 1;
    }
    char server_ans[1025] = { 0 };
    recv(s, server_ans, 1024, 0);
    cout << "\n@ Received message: " << server_ans << endl;
    if (sliceCharArr(server_ans, CODE_INDEX, SIZE_INDEX) == S_RECONNECT_FAILED) {
        cout << "- Reconnect failed" << endl;
        return 1;
    }

    cout << "- Reconnect succeed" << endl;
    string enAESKey = sliceCharArr(server_ans, 8, strlen(server_ans));
    keys cKeys = loadPrivateKey();
    aes_key = decryptAESKey(enAESKey, cKeys);
    cout << "- AES key Decrypted" << endl;

    return 0;
}


int main(int argc, char const* argv[])
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in sa = defSockaddr();
    connect(s, (struct sockaddr*)&sa, sizeof(sa));

    string AESKey;
    fstream me_file("me.info");
    if (!me_file.is_open()) {
        me_file.close();
        cout << "- File 'me.info' not found" << endl;
        if (protocol(registation, s, AESKey)) return 1;
    }
    else {
        me_file.close();
        cout << "- File 'me.info' found" << endl;
        if (reconnect(s, AESKey) == 1)
            if (protocol(registation, s, AESKey)) return 1;
    }
    int crc_ok = 0;
    for (int i = 0; i < MAX_ATEMPS+1; i++) {
        if (protocol(sendfile, s, AESKey, i)) return 1;
        if(i!= MAX_ATEMPS)
            if (protocol(checkCrc, s, crc_ok)) return 1;
        if (crc_ok) break;
    }

    closesocket(s);
    cout << "- Socket closed";

    return 0;
}