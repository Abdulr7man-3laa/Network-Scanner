# Import required libraries
import scapy.all as scapy  # library for network scanning functionality
import optparse  # for parsing command line arguments
import subprocess # for executing shell commands
import re # for regular expressions

def getIPAddress():
    """
    Get the current machine's IP address.
    
    Returns:
        str: The extracted IP address.
    """
    # using scapy
    # return scapy.get_if_addr(scapy.conf.iface)
    
    # using subprocess and regex
    try:
        # Execute the 'ifconfig' command to retrieve network interface details
        ifconfig_output = subprocess.check_output("ifconfig", shell=True).decode("utf-8")
        
        # Search for an IP address pattern in the output
        ip_match = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ifconfig_output)
        
        # If an IP address is found, return it
        if ip_match:
            return ip_match.group(0)
    except Exception as e:
        # If an error occurs, return an error message
        return f"Error retrieving IP: {e}"
    
    
    
def isValidPattern(network_ip):
    """ 
    Check if the provided network IP range is valid.
    
    Args:
        network_ip (str): The network IP range to check.
    
    Returns:
        bool: True if the network IP range is valid, False otherwise.
    """
    return bool(re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", network_ip))
    
def arguments():
    """
    Parse and handle command-line arguments for the network scanner.
    
    This function sets up command-line argument parsing using optparse,
    specifically to handle the network IP range that will be scanned.
    
    Returns:
        optparse.Values: Object containing the parsed command-line options,
                        specifically the network_ip value.
    """
    
    # Create an OptionParser object to handle command-line arguments
    parser = optparse.OptionParser()
    
    # Add option for network IP range with -r or --range flags
    parser.add_option("-r", "--range", dest="network_ip", 
                     help="Network IP range to scan (Ex: 192.168.65.1/24)")
    
    # Parse the command-line arguments into options and arguments
    (options, arguments) = parser.parse_args()
        
    # Check if the network IP range was provided
    if not options.network_ip:
        print("\n[i] Connected IP address: " + getIPAddress())
        print("[-] Error: Please specify a network IP range, use --help for more info.")
        exit()

    # Validate the format of the provided network IP range
    if not isValidPattern(options.network_ip):
        print("\n[i] Connected IP address: " + getIPAddress())
        print("[-] Error: Please specify a valid network IP range, use --help for more info.")
        exit()

    # If all checks pass, return the options object
    return options


def scan(network_ip):
    """
    Perform an ARP scan on the specified network IP range.
    
    This function creates and sends ARP requests to discover active hosts
    on the network. It broadcasts ARP requests and collects responses to
    identify active IP addresses and their corresponding MAC addresses.
    
    Args:
        network_ip (str): The network IP range to scan (Ex: "192.168.65.1/24")
        
    Returns:
        list: A list of dictionaries containing discovered clients,
              where each dictionary has 'IP' and 'MAC' keys.
    """
    
    # Create ARP request packet for the specified IP range
    arpRequest = scapy.ARP(pdst=network_ip)
    
    # Create Ethernet frame with broadcast MAC address
    arpBroadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Combine Ethernet frame and ARP request
    arpRequestBroadcast = arpBroadcast/arpRequest
    
    # Send packets and capture responses, timeout after 1 second
    # [0] gets the answered packets, ignoring unanswered ones
    responses = scapy.srp(arpRequestBroadcast, timeout=1, verbose=False)[0]
    
    # Initialize empty list to store discovered clients
    clients_list = []
    
    # Process each response and extract IP and MAC addresses
    for ans in responses:
        # Create dictionary with IP and MAC address from response
        client_info = {"IP": ans[1].psrc, "MAC": ans[1].hwsrc}
        # Add client information to the list
        clients_list.append(client_info)
    
    # Return the list of discovered clients
    return clients_list

def displayInfo(clients):
    """
    Display the discovered network clients in a formatted table.
    
    This function prints a table showing the IP and MAC addresses
    of all discovered clients on the network.
    
    Args:
        clients (list): List of dictionaries containing client information,
                       where each dictionary has 'IP' and 'MAC' keys.
    """

    # Check if any clients were found
    if clients:
        print("-" * 49)
        print("[i] IP address\t\t\tMAC address")
        print("-" * 49)
        for client in clients:
            print(f"[{clients.index(client)+1}] {client['IP']}\t\t{client['MAC']}")
    else:
        # If no clients were found
        print("No clients found on the network.")

# Main execution block
if __name__ == "__main__":
    # Get command-line arguments
    options = arguments()
    
    # Perform network scan with provided IP range
    scan_result = scan(options.network_ip)
    
    # Display results in formatted table
    displayInfo(scan_result)
