#!/usr/bin/python3
import sniffer

# GitHub repository: https://github.com/Albisyx/PyNetSniffer


def main():
    interface = sniffer.list_interfaces()
    sniffer.start_sniffing(interface)


if __name__ == '__main__':
    main()


