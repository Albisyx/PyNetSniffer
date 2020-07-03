#!/usr/bin/python3
import sniffer


def main():
    interface = sniffer.list_interfaces()
    sniffer.start_sniffing(interface)


if __name__ == '__main__':
    main()


