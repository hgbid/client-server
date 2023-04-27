#pragma once

# define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <WinSock2.h>
#include <Windows.h>
#include <fstream>
#include <string>

#include "crypt.h"


#pragma comment(lib, "Ws2_32.lib")

# define PORT 8080
# define CLIENT_VERSION 3

# define C_REGISTER_CODE        "1100"
# define C_SEND_PUBL_KEY_CODE   "1101"
# define C_RECONNECT_CODE       "1102"
# define C_SEND_FILE_CODE       "1103"
# define C_CRC_OK_CODE          "1104"
# define C_CRC_ERROR_SA_CODE    "1105"
# define C_CRC_ERROR_END_CODE   "1106"

# define S_REGISTER_SUCC_CODE   "2100"
# define S_REGISTER_FAIL_CODE   "2101"
# define S_OK_END               "2103"
# define S_RECONNECT_FAILED     "2106"
# define S_GENERAL_ERROR        "2107"

# define FILENAME_SIZE 255
# define FILESIZE_SIZE 10
# define PAYLOAD_LEN_SIZE 4
# define MAX_ATEMPS 3

# define CODE_INDEX 1
# define SIZE_INDEX 5
# define PAYLOAD_INDEX = 41

using namespace std;
using namespace CryptoPP;


class WSA {
public:
    WSA() {
        WSADATA wsaData;
        int ret = WSAStartup(MAKEWORD(2, 2),
            &wsaData);
    }
    ~WSA() {
        WSACleanup();
    }
};



template <typename Func, typename... Args>
int protocol(Func func, Args&&... args) {
    int attempts = 0;
    while (func(forward<Args>(args)...) != 0) {
        attempts++;
        if (attempts > 2) {
            std::cout << "- Fatal error\n- Exit(fail)" << std::endl;
            return 1;
        }
    }
    return 0;
}

string getConnrectionDetails() {
    fstream tr_file("transfer.info");
    string adrss = "";
    string clnt_name = "";

    if (!tr_file.is_open()) {
        cout << "Error: File 'transfer.info' not found" << endl;
        return 0;
    }
    try {
        getline(tr_file, adrss);
        tr_file.close();
    }
    catch (...) {
        cout << "Error in file 'transfer' format" << endl;
    }
    return adrss;

}
sockaddr_in defSockaddr() {
    struct sockaddr_in sa = { 0 };
    sa.sin_family = AF_INET;
    string adress = getConnrectionDetails();
    size_t colon_pos = adress.find(":");
    string ip_address = adress.substr(0, colon_pos);
    string port_number = adress.substr(colon_pos + 1);

    sa.sin_addr.s_addr = inet_addr(ip_address.data());
    sa.sin_port = htons(stoi(port_number));
    return sa;
}

string sliceCharArr(char* org, int startin, int endin) {
    string substr = "";
    for (int i = startin; i < endin; i++) {
        substr.push_back(org[i]);
    }
    return substr;
}

string paddMassage(int length, string massage) {
    string paddMassage = massage;
    char c = ' ';
    while (paddMassage.length() < length) {
        paddMassage += c;
    }
    return paddMassage;
}

string makeRequest(string cID, string code, string payload) {
    if (cID.empty()) cID = "00000000000000000000000000000000";
    string request = cID + to_string(CLIENT_VERSION) + code + 
        paddMassage(PAYLOAD_LEN_SIZE, to_string(payload.length())) + payload;

    return request;
}

string arrengeMassage(char input[]) {
    string str(input);
    str.erase(std::remove(str.begin(), str.end(), ' '), str.end());
    return str;
}

int getFileName(string& fn) {
    string filename = "transfer.info";
    ifstream file(filename);
    if (!file) {
        cerr << "Could not open file: " << filename << endl;
        return 1;
    }
    string line;
    for (int i = 0; i < 3; i++) {
        getline(file, line);
    }
    fn = line;
    return 0;
}

string getCID() {
    string filename = "me.info";
    ifstream file(filename);
    if (!file) {
        cerr << "Could not open file: " << filename << endl;
        return "";
    }
    string line;
    for (int i = 0; i < 2; i++) {
        getline(file, line);
    }
    return line;
}

string getClientName() {
    string filename = "me.info";
    ifstream file(filename);
    if (!file) {
        cerr << "Could not open file: " << filename << endl;
        return "";
    }
    string line;
    getline(file, line);
    return line;
}