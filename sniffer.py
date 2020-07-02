import logging
import datetime
from scapy.all import *
from IDS import Detector

# This module will be responsible of listing the available interfaces
# to the user and start listening on the selected one

# Initial configurations for the logging module
packets_logger = logging.getLogger(__name__)
packets_logger.setLevel(logging.DEBUG)
# Creation of the FileHandler
current_datetime = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
file_logs = logging.FileHandler("/Users/albertospadoni/Desktop/logs/captured_packets-{}".format(current_datetime))
file_logs_format = logging.Formatter("%(asctime)s::%(levelname)s:: %(message)s")
file_logs.setFormatter(file_logs_format)
# Creation of the StreamHandler
console_logs = logging.StreamHandler()
# Adding the handler just created
packets_logger.addHandler(file_logs)
packets_logger.addHandler(console_logs)

# Let's create the instance of the class responsible for the attacks detections and packets logging
ids = Detector()


# Method for listing all the available interfaces to the user.
# It returns the selected interface
def list_interfaces():
    print("Here's the available interfaces that i can listen to!")
    print("Please select one by typing the corresponding number:")
    interfaces = get_if_list()

    i = 1
    for item in interfaces:
        print("[{}] {}".format(i, item))
        i += 1

    selection = get_interface(len(interfaces))
    packets_logger.debug("Start listening on interface {}".format(interfaces[selection - 1]))
    return interfaces[selection - 1]


# Method for input validation
def get_interface(bound):
    while True:
        # Check if the input value is a number
        try:
            value = int(input("Selected interface -> "))
        except ValueError:
            print("This is an invalid choice...")
            continue

        # Check if the input value is in the valid range
        if value <= 0 or value > bound:
            print("Interface not in the list...")
            continue
        else:
            break
    return value


def start_sniffing(interface):
    sniff(iface=interface,          # interface to listen on
          prn=ids.inspect_packets,  # function to execute for each sniffed packet
          store=0)                  # sniffed packets will not stored in RAM
