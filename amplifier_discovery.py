import requests
from pymemcache import Client
from scapy.all import *
from scapy.layers.ntp import NTPHeader
import dns.resolver
import time
import dns.resolver
from scapy.layers.inet import IP, UDP
import json
from server_collection import load_env_file


def nameserver_collection(input_filename, output_filename):
    """
    This function reads domain names from an input file, performs DNS NS queries to
    get authoritative name servers, and stores the mappings in a JSON file.

    Parameters:
    input_filename (str): The path to the input file containing domain names.
    output_filename (str): The path to the output JSON file where mappings will be saved.
    """
    with open(input_filename, 'r') as file:
        domain_names = file.read().split('\n')

    authoritative_dns_to_domain = {}

    # Iterate through a subset of .fr domains (for example purposes, 100 to 200)
    for domain in domain_names:
        try:
            # Perform a DNS NS query to get authoritative name servers
            ns_records = dns.resolver.resolve(domain, 'NS')
            authoritative_dns = [str(ns.target)[:-1] for ns in ns_records]
            # Store the authoritative DNS servers for the domain
            for authoritative_server in authoritative_dns:
                # Create the reverse mapping from authoritative DNS to domain
                authoritative_dns_to_domain.setdefault(authoritative_server, []).append(domain)
        except dns.resolver.NoNameservers:
            print(f"No authoritative DNS servers found for {domain}")
        except dns.resolver.NXDOMAIN:
            print(f"Domain {domain} does not exist")
        except dns.resolver.NoAnswer:
            print(f"Domain {domain} didn't give an answer")
        except dns.resolver.Timeout:
            print(f"Domain {domain} gave a timeout")

    # Save the authoritative DNS to domain mappings into a JSON file
    with open(output_filename, "w") as file:
        json.dump(authoritative_dns_to_domain, file, indent=4)


def transform_reverse_dns_to_ip(input_filename, output_filename):
    """
    This function reads authoritative DNS servers from a JSON file, resolves their IP addresses,
    and writes the updated mappings to another JSON file.

    Parameters:
    input_filename (str): The path to the input JSON file containing reverse DNS mappings.
    output_filename (str): The path to the output JSON file where updated mappings will be saved.
    """
    with open(input_filename, 'r') as file:
        reverse_dns_servers = json.load(file)

    updated_authoritative_dns = {}
    for reverse_dns, domains in list(reverse_dns_servers.items()):
        nameserver_ip = get_nameserver_ip(reverse_dns)
        if nameserver_ip:
            updated_authoritative_dns[nameserver_ip] = domains
        else:
            print('Could not find the IP of: ' + reverse_dns)

    # Save the updated mappings into a JSON file
    with open(output_filename, "w") as file:
        json.dump(updated_authoritative_dns, file, indent=4)


def get_nameserver_ip(reverse_dns):
    """
    This function performs a DNS A query to get the IP address of a given reverse DNS name.

    Parameters:
    reverse_dns (str): The reverse DNS name to be resolved.

    Returns:
    str: The IP address of the reverse DNS name, or None if resolution fails.
    """
    try:
        result = dns.resolver.resolve(reverse_dns, 'A', lifetime=5)
        ip_address = result[0].address
        return ip_address
    except dns.resolver.NoAnswer:
        print("No A record found for the given reverse DNS value.")
        return None
    except dns.resolver.NXDOMAIN:
        print("The reverse DNS value does not exist.")
        return None
    except dns.resolver.Timeout:
        print("DNS resolution timed out")
        return None
    except dns.exception.DNSException as e:
        print("An error occurred:", e)
        return None


def extract_valid_geolocation(dm_to_ns_ips, filtered_outfile):
    """
    This function filters authoritative DNS servers located in France from a JSON file
    and writes the filtered results to another JSON file.

    Parameters:
    dm_to_ns_ips (str): The path to the input JSON file containing domain to DNS IP mappings.
    filtered_outfile (str): The path to the output JSON file where filtered results will be saved.
    """
    with open(dm_to_ns_ips, 'r') as file:
        authoritative_dns = json.load(file)

    filtered_authoritative_dns = {}
    for ip, domains in authoritative_dns.items():
        if check_ip_location(ip):
            filtered_authoritative_dns[ip] = domains

    # Save the filtered authoritative DNS servers into a JSON file
    with open(filtered_outfile, "w") as file:
        json.dump(filtered_authoritative_dns, file, indent=4)


def check_ip_location(ip_address):
    """
    This function checks if a given IP address is located in France using the ipinfo API.

    Parameters:
    ip_address (str): The IP address to be checked.

    Returns:
    bool: True if the IP address is located in France, False otherwise.
    """
    load_env_file('.env')
    api_key = os.getenv('IPINFO_API_KEY')
    if not api_key:
        raise ValueError("IPINFO_API_KEY environment variable must be set")

    url = f'https://ipinfo.io/{ip_address}/json?token={api_key}'

    try:
        response = requests.get(url)
        data = response.json()

        if 'country' in data and data['country'] == 'FR':
            print(f"The IP address {ip_address} is located in France.")
            return True
        else:
            print(f"The IP address {ip_address} is not located in France.")
            return False
    except Exception as e:
        print("An error occurred:", e)
        return False


def filter_open_recursive_dns(input_filename, output_filename):
    """
    This function filters open recursive DNS servers from a JSON file and writes the
    filtered results to another JSON file.

    Parameters:
    input_filename (str): The path to the input JSON file containing DNS server information.
    output_filename (str): The path to the output JSON file where filtered results will be saved.
    """
    # Open the JSON file and load the data
    with open(input_filename, 'r') as file:
        dns_servers = json.load(file)

    filtered_data = []
    # Extract IP addresses from the JSON data
    for dns_server in dns_servers:
        ip = dns_server['ip']
        print(ip)
        if check_open_recursive_dns('google.com', ip):
            filtered_data.append(dns_server)

    # Save the filtered DNS servers into a JSON file
    with open(output_filename, "w") as file:
        json.dump(filtered_data, file, indent=4)


def check_open_recursive_dns(domain, nameserver):
    """
    This function checks if a DNS server is open and recursive by performing a DNS query.

    Parameters:
    domain (str): The domain to be resolved.
    nameserver (str): The DNS server to be checked.

    Returns:
    bool: True if the DNS server is open and recursive, False otherwise.
    """
    try:
        my_resolver = dns.resolver.Resolver()
        my_resolver.nameservers = [nameserver]
        my_resolver.lifetime = my_resolver.timeout = 3

        response = my_resolver.resolve(domain, 'A')
        return True
    except dns.resolver.NXDOMAIN:
        print("No such domain")
    except dns.exception.Timeout:
        print("Timeout occurred")
    except dns.resolver.NoNameservers:
        print("No name servers found")
    except dns.resolver.NoAnswer:
        print("No answer found for the query")
    except Exception as e:
        print(f"An error occurred: {e}")

    return False


def filter_open_ntp_servers(input_filename, output_filename):
    """
    Filters open NTP servers from a list of NTP servers in the input file and saves them to the output file.

    Parameters:
    input_filename (str): Path to the input file containing a list of NTP servers.
    output_filename (str): Path to the output file where the filtered open NTP servers will be saved.

    The function reads the input file to get the list of NTP servers, checks which servers are open by
    testing UDP response, and writes the open servers to the output file.
    """

    # Open the input file and load the list of NTP servers
    with open(input_filename, 'r') as file:
        ntp_servers = json.load(file)

    # Initialize a list to store NTP servers that reply to UDP requests
    replies_to_udp = []

    # Loop through the first 10 NTP servers in the list
    for ntp_server in ntp_servers:
        # Extract the IP address of the NTP server
        ip = ntp_server['ip']
        # Check if the NTP server is open by testing UDP response
        if check_open_ntp(ip):
            # If the server replies, add it to the replies_to_udp list
            replies_to_udp.append(ntp_server)

    # Write the filtered list of open NTP servers to the output file
    with open(output_filename, "w") as file:
        json.dump(replies_to_udp, file, indent=4)


def check_open_ntp(ntp_server):
    """
    Check if the server is open and running NTP service

    Args:
        ntp_server (str): The IP address of the NTP server to be tested.

    Returns:
        float: The amplification factor, which is the ratio of the total response size
               to the request size.
    """
    try:
        # Craft the simple NTP client request packet
        ntp_request = IP(dst=ntp_server) / UDP(sport=RandShort(), dport=123) / NTPHeader(mode=3)

        # Send the packet and wait for a response
        send(ntp_request)

        # Capture response packet
        response = sr1(ntp_request, timeout=2, verbose=0)

        # Check if the response is a valid NTP response with mode 4 (server)
        if response and response.haslayer(NTPHeader) and response[NTPHeader].mode == 4:
            return True
        return False
    except Exception as e:
        print(f"Error during NTP check: {e}")
        return False


def check_memcached_udp(memcached_server):
    """
    Check if a Memcached server is open by responding to a UDP "stats" request and calculate the amplification factor.

    Args:
        memcached_server (str): The IP address of the Memcached server to be tested.

    Returns:
        str: The response from the Memcached server if it responds.
        bool: False if the Memcached server does not respond.
    """
    # Craft a UDP packet with the "stats" command
    memcached_request = IP(dst=memcached_server) / UDP(sport=RandShort(), dport=11211) / Raw(
        load="\x00\x01\x00\x00\x00\x01\x00\x00stats\r\n")

    request_size = len(memcached_request[Raw])

    # Send the packet and wait for a response
    response = sr1(memcached_request, verbose=0, timeout=3)

    # Check if a response was received
    if response and response.haslayer(Raw) and 'dest-unreach' not in str(response):
        stats_response = response[Raw].load.decode('utf-8')
        response_size = len(response[Raw])
        amplification_factor = response_size / request_size

        # Print the amplification factor
        print("Amplification Factor:", amplification_factor)

        return stats_response
    else:
        print(f"Memcached server with IP {memcached_server} did not respond to UDP.")

    return False


def filter_open_memcached_servers(input_file, output_file):
    """
    Filters open Memcached servers from a list of servers in the input file and updates the output file with the results.

    Parameters:
    input_file (str): Path to the input file containing a list of Memcached server IPs.
    output_file (str): Path to the output file where the filtered open Memcached servers will be saved.

    The function reads the input file to get the list of Memcached servers, checks which servers are open by
    testing UDP response, and updates the output file with the new open servers.
    """

    # Open the input file and read the list of Memcached servers
    with open(input_file, 'r') as file:
        memcached_servers = json.load(file)

    # Initialize a dictionary to store open Memcached servers and their responses
    open_memcached_servers = {}

    # Loop through each IP address in the list of Memcached servers
    for memcached_server in memcached_servers:
        ip = memcached_server['ip']
        # Check if the Memcached server is open by testing UDP response
        response = check_memcached_udp(ip)
        if response:
            # If the server is open, add it to the open_memcached_servers dictionary
            open_memcached_servers[ip] = response

    # Write the updated dictionary with the new open Memcached servers to the output file
    with open(output_file, "w") as file:
        json.dump(open_memcached_servers, file, indent=4)


def extract_memcached_servers_keys(input_filename, output_filename):
    """
    Extracts keys from memcached servers listed in the input file and saves them to the output file.

    Parameters:
    input_filename (str): Path to the input file containing a list of memcached servers.
    output_filename (str): Path to the output file where the extracted keys will be saved.

    The function reads the input file to get the list of memcached servers, extracts the keys from each server,
    and writes the extracted keys to the output file.
    """
    # Open the input file and load the list of memcached servers
    with open(input_filename, "r") as file:
        memcached_servers = json.load(file)

    # Initialize a dictionary to store the keys for each server
    new_keys = {}

    # Loop through each memcached server IP address
    for ip in memcached_servers.keys():
        # Extract keys from the memcached server using the get_memcached_keys function
        keys = get_memcached_keys(ip)
        # Store the extracted keys in the new_keys dictionary
        new_keys[ip] = keys

    # Write the updated dictionary with the extracted keys to the output file
    with open(output_filename, "w") as file:
        json.dump(new_keys, file, indent=4)


def get_memcached_keys(memcached_server):
    """
    Retrieve the top 100 keys from a Memcached server on TCP based on the value size to key length ratio.

    Args:
        memcached_server (str): The IP address of the Memcached server to be tested.

    Returns:
        list: A list of the top 100 keys with the highest value size to key length ratio.
    """
    try:
        # Create a Memcached client
        mc = Client((memcached_server, 11211))

        # Send the 'stats slabs' command to retrieve slab IDs
        stats_items = mc.stats('slabs')

        # Extract slab IDs from the stats
        all_slabs = []
        for slab_id, value in stats_items.items():
            parts = slab_id.split(b':')
            part = parts[0]
            all_slabs.append(part)

        # Remove non-slab entries and keep only unique slab IDs
        all_slabs.remove(b'active_slabs')
        all_slabs.remove(b'total_malloced')
        unique_slab_ids = set(all_slabs)

        # Dictionary to store keys and their value size to key length ratio
        all_keys = {}

        for slab_id in unique_slab_ids:
            time.sleep(0.5)  # Add delay to avoid overloading the server

            # Send the 'stats cachedump' command to retrieve keys for the slab
            stats_cachedump = mc.stats('cachedump', slab_id, '0')

            for key, value in stats_cachedump.items():
                value_size = int(value.decode().split(' b;')[0][1:])
                if value_size / len(key.decode()) > 100:
                    ratio = value_size / len(key.decode())
                    all_keys[key.decode()] = ratio

        # Sort the keys by their ratio in descending order and select the top 100
        sorted_keys = sorted(all_keys.items(), key=lambda item: item[1], reverse=True)
        top_100_keys = dict(sorted_keys[:100])

        return list(top_100_keys.keys())

    except Exception as e:
        print("Could not retrieve any keys: ", str(e))
        return []


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python amplifier_discovery.py <method_name> <args>")
        sys.exit(1)

    method_name = sys.argv[1]
    args = sys.argv[2:]

    try:
        method = getattr(sys.modules[__name__], method_name)
    except AttributeError:
        print(f"Unknown method: {method_name}")
        sys.exit(1)

    method(*args)