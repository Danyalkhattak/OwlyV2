
# OwlyV2 - Advanced Brute Force Tool

OwlyV2 is an advanced brute force tool designed for penetration testing. This tool supports a variety of attack modes, including SSH, FTP, RDP, SMB, MySQL, and WordPress. It utilizes multi-threading to enhance performance and efficiency, making it a powerful tool for security professionals.

## Features
- **Multi-threaded attacks**: Supports concurrent attack attempts to improve speed and efficiency.
- **Multiple attack modes**: Includes SSH, FTP, RDP, SMB, MySQL, and WordPress brute-force attack capabilities.
- **Logging**: Keeps track of all login attempts with detailed output.
- **Optimized for performance**: Efficient and fast, designed for high-performance brute-force attacks.

## Installation & Usage

### Step 1: Clone the Repository
First, clone the repository to your local machine:

```bash
git clone https://github.com/Danyalkhattak/OwlyV2.git
cd OwlyV2
```

### Step 2: Install Dependencies
OwlyV2 requires several dependencies. Install them by running the following command (Ubuntu/Debian):

```bash
sudo apt-get install libssh-dev libcurl4-openssl-dev libpcap-dev libssl-dev
```

These dependencies include libraries for SSH, FTP, and packet capture, as well as necessary SSL and CURL libraries for various brute force methods.

### Step 3: Compile the Code
Once the dependencies are installed, compile the source code with `g++`:

```bash
g++ -o owlyv2 bruteforce.cpp -lssh -lcurl -lssl -lpcap -pthread
```

This will generate the executable file `owlyv2`.

### Step 4: Run the Program
You can now run OwlyV2 by specifying the attack mode, target, username, and wordlist. The syntax for usage is:

```bash
./owlyv2 <mode> <target> <username> <wordlist>
```

#### Parameters:
- `<mode>`: The type of attack (options: `ssh`, `ftp`, `rdp`, `smb`, `mysql`, `wordpress`).
- `<target>`: The IP address or domain of the target server.
- `<username>`: The username you want to attempt.
- `<wordlist>`: A file containing the list of passwords to try.

#### Example:
```bash
./owlyv2 ssh 192.168.1.1 user passwords.txt
```

This will attempt to brute force the SSH login for the specified `user` on the target server `192.168.1.1` using passwords from `passwords.txt`.

## Requirements
- **libssh**: For SSH-based brute force.
- **libcurl**: For FTP-based brute force.
- **openssl**: For hashing operations.
- **pcap**: For packet capture operations (if needed).
- **curl**: For making HTTP requests (used in FTP and WordPress attacks).
- **Additional libraries**: `libpcap-dev`, `libssl-dev`, `libcurl4-openssl-dev`.

### Install dependencies (Linux/Ubuntu):

```bash
sudo apt-get install libssh-dev libcurl4-openssl-dev libpcap-dev libssl-dev
```

## Disclaimer

OwlyV2 is intended for educational purposes and ethical penetration testing only. Use this tool responsibly and with the permission of the system owner. Unauthorized access to systems is illegal and unethical.

## Contributing

If you would like to contribute to this project, feel free to fork the repository, make your changes, and submit a pull request. Any improvements, bug fixes, or new features are welcome!

## License

OwlyV2 is released under the MIT License. See [LICENSE](LICENSE) for more information.
