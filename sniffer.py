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

    selection = get_interface(len(interfaces))
    print(interfaces[selection-1])


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
        if value < 0 or value > bound:
            print("Interface not in the list...")
            continue
        else:
            break

    return value