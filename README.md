# PyNetSniffer
PyNetSniffer is a command-line tool written in Python 3.8. Taking advantage of the Scapy module, it performs **packet analyzing** and some basic **intrusion detection** operations.
The tool is able to detect the following types of suspicious traffic:
- port scanning attempts with
    + TCP FIN packets
    + TCP X-Mas packets
- SYN Flood attacks

### Installation
Most modules that PyNetSniffer uses are built-in in Python 3.x. The only one that is required to install is Scapy. For an easy and quick installation, create a virtual environment inside the tool's folder and type the following command:

`pip3 install -r requirements.txt`

### Usage
In order to run the program, on Unix-like operating systems just type `./main.py`. You will be asked to select the network interface on which the packets will be sniffed. After that, the tool will start capturing and logging network traffic on a file. The default location is **_/var/log/PyNetSniffer/_**. In case PyNetSniffer detects an attack, it logs the warning both to a separated file and on the console. Since the logging path includes some system directories, make sure  to run the tool with superuser privileges unless you change the location.

The repository also provides a little Python script that can be userd to perform the network attacks mentioned above in order to test the IDS capabilities. The script requires 3 arguments in order to be executed:
1. `-i` or `--iface` with the interface on which perform the attacks
2. `-ip` with the IPv4 address of the target
3. `-n` with the number of packets to send for each attack. This arguments is not mandatory, the default value is 600.

The `-h`, `--help` options can also be used to display the help menu.
