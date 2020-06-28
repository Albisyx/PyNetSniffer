from scapy.all import *

# This module will be responsible of listing the available interfaces
# to the user and start listening on the selected one


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
    selection = int(input("Selected interface -> "))
    print(interfaces[selection-1])