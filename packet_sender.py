import json
from scapy.all import *
from scapy.layers.dns import DNS, DNSRROPT, DNSQR
from scapy.layers.inet import IP, UDP


def measure_dns_authoritative_packet_size(dns_server, domain_name):
    """
    Measures the amplification factor of an authoritative DNS server for a given domain name.

    Parameters:
    dns_server (str): The IP address of the DNS server.
    domain_name (str): The domain name to query.

    Returns:
    float: The amplification factor.
    """
    print('Trying ' + domain_name + ' with ' + dns_server)

    # Craft DNS query packet for authoritative DNS server
    dns_request = IP(dst=dns_server) / UDP(sport=RandShort(), dport=53) / DNS(ad=1,
                                                                              qd=DNSQR(qname=domain_name, qtype=255),
                                                                              ar=DNSRROPT(rclass=4096, z=1))

    # Measure the size of the request packet
    request_size = len(dns_request[UDP].payload)

    # Send the DNS request packet
    send(dns_request, verbose=0)

    # Sniff the response packet
    responses = sniff(lfilter=lambda x: validate_server_response(x, dns_server, 53), timeout=2)

    # Calculate the size of the response packet
    response_size = 0
    for response in responses:
        response_size += response[UDP].len - 8

    print(response_size / request_size)

    return response_size / request_size


def measure_dns_recursive_packet_size(dns_server, domain_name):
    """
    Measures the amplification factor of a recursive DNS server for a given domain name.

    Parameters:
    dns_server (str): The IP address of the DNS server.
    domain_name (str): The domain name to query.

    Returns:
    float: The amplification factor.
    """
    print('Trying ' + domain_name + ' with ' + dns_server)

    # Craft DNS query packet for recursive DNS server
    dns_request = IP(dst=dns_server) / UDP(sport=RandShort(), dport=53) / DNS(rd=1,
                                                                              ad=1,
                                                                              qd=DNSQR(qname=domain_name, qtype=255),
                                                                              ar=DNSRROPT(rclass=4096, z=1),
                                                                              tc=0)

    # Measure the size of the request packet
    request_size = len(dns_request[UDP].payload)

    # Send the DNS request packet
    send(dns_request, verbose=0)

    # Sniff the response packet
    responses = sniff(lfilter=lambda x: validate_server_response(x, dns_server, 53), timeout=2)

    # Calculate the size of the response packet
    response_size = 0
    for response in responses:
        response_size += response[UDP].len - 8

    return response_size / request_size


def dns_experiment_authoritative(input_filename, output_filename):
    """
    Conducts an experiment to measure DNS amplification factors for authoritative DNS servers.

    Parameters:
    input_filename (str): Path to the input file containing authoritative DNS server information.
    output_filename (str): Path to the output file where the experiment results will be saved.
    """
    # Open the input file and load the list of authoritative DNS servers and domains
    with open(input_filename, 'r') as file:
        authoritative_dns = json.load(file)

    # Initialize a dictionary to store the results of the experiment
    results = {}

    # Loop through the first 10 DNS servers in the list
    for ip, domains in authoritative_dns.items():
        results[ip] = {}
        for domain in domains:
            # Measure the amplification factor for each domain on the DNS server
            amplification_factor = measure_dns_authoritative_packet_size(ip, domain)
            results[ip][domain] = amplification_factor

    # Write the results of the experiment to the output file
    with open(output_filename, "w") as file:
        json.dump(results, file, indent=4)


def dns_experiment_recursive(input_filename, output_filename, domain_name):
    """
    Conducts an experiment to measure DNS amplification factors for recursive DNS servers.

    Parameters:
    input_filename (str): Path to the input file containing recursive DNS server information.
    output_filename (str): Path to the output file where the experiment results will be saved.
    domain_name (str): The domain name to query.
    """
    # Open the input file and load the list of recursive DNS servers
    with open(input_filename, 'r') as file:
        recursive_dns = json.load(file)

    # Initialize a dictionary to store the results of the experiment
    results = {}

    # Loop through each DNS server in the list
    for dns_server in recursive_dns:
        ip = dns_server['ip']
        results[ip] = {}
        # Measure the amplification factor for the specified domain on the DNS server
        amplification_factor = measure_dns_recursive_packet_size(ip, domain_name)
        results[ip][domain_name] = amplification_factor

    # Write the results of the experiment to the output file
    with open(output_filename, "w") as file:
        json.dump(results, file, indent=4)


def measure_ntp_packet_size(ntp_server):
    """
    Measure the amplification factor of an NTP server by sending an NTP monlist request.

    Args:
        ntp_server (str): The IP address of the NTP server to be tested.

    Returns:
        float: The amplification factor.
    """
    # Craft the NTP Monlist request packet
    data = "\x17\x00\x03\x2a" + "\x00" * 4
    ntp_request = IP(dst=ntp_server) / UDP(sport=RandShort(), dport=123) / Raw(load=data)

    # Measure the size of the request packet
    request_size = len(ntp_request[UDP].payload)

    # Send the NTP Monlist request packet
    send(ntp_request, verbose=0)

    # Sniff the response packets
    responses = sniff(lfilter=lambda x: validate_server_response(x, ntp_server, 123), timeout=2)

    response_size = 0
    # Measure the response size of each packet
    for response in responses:
        response_size += len(response[UDP].payload)

    # Print the sizes of the request and response packets
    print("Request Size:", request_size, "bytes")
    print("Response Size:", response_size, "bytes")
    print(response_size / request_size)
    return response_size / request_size


def ntp_experiment(input_filename, output_filename):
    """
    Conducts an experiment to measure NTP packet sizes from a list of NTP servers.

    Parameters:
    input_filename (str): Path to the input file containing a list of NTP servers.
    output_filename (str): Path to the output file where the experiment results will be saved.

    The function reads the input file to get the list of NTP servers, measures the packet size
    for each server, and writes the results to the output file.
    """

    # Open the input file and load the list of NTP servers
    with open(input_filename, 'r') as file:
        ntp_servers = json.load(file)

    # Initialize a dictionary to store the results of the experiment
    results = {}

    # Loop through the first 5 NTP servers in the list
    for ntp_server in ntp_servers:
        # Extract the IP address of the NTP server
        ip = ntp_server['ip']
        # Measure the NTP packet size for the server and store it in the results dictionary
        results[ip] = measure_ntp_packet_size(ip)

    # Write the results of the experiment to the output file
    with open(output_filename, "w") as file:
        json.dump(results, file, indent=4)


def measure_memcached_packet(memcached_server, key):
    """
    Measure the amplification factor of a Memcached server by sending a Memcached "get" request with a key

    Args:
        memcached_server (str): The IP address of the Memcached server to be tested.
        key (str): The key to retrieve the associated value from the Memcached server.

    Returns:
        float: The amplification factor.
    """
    # Craft the Memcached get request packet
    memcached_request = IP(dst=memcached_server) / UDP(sport=RandShort(), dport=11211) / Raw(
        load="\x00\x01\x00\x00\x00\x01\x00\x00get {}\r\n".format(key))

    # Send the Memcached get request packet
    send(memcached_request)

    # Measure the size of the request packet
    request_size = len(memcached_request[UDP].payload)

    # Sniff the response packets
    responses = sniff(lfilter=lambda x: validate_server_response(x, memcached_server, 11211), timeout=3)

    response_size = 0
    # Measure the response size of each packet
    for response in responses:
        response_size += len(response[UDP].payload)

    # Print the sizes of the request and response packets
    print("Request Size:", request_size, "bytes")
    print("Response Size:", response_size, "bytes")
    print("Amplification Factor:", response_size / request_size)

    return response_size / request_size


def memcached_experiment(input_filename, output_filename):
    """
    This function reads a list of memcached servers from an input file, performs an experiment
    to measure packet data, and saves the results to an output file.

    Parameters:
    input_filename (str): The path to the input JSON file containing memcached servers and keys.
    output_filename (str): The path to the output JSON file where results will be saved.
    """
    with open(input_filename, "r") as file:
        memcached_servers = json.load(file)

    results = {}
    for ip, keys in memcached_servers.items():
        results[ip] = {}
        for key in keys:
            # Measure the memcached packet for the given IP and key
            baf = measure_memcached_packet(ip, key)
            results[ip][key] = baf

    # Write the results to the output JSON file
    with open(output_filename, "w") as file:
        json.dump(results, file, indent=4)


def compute_baf_for_stats(input_filename, output_filename):
    """
    This function reads previous statistics from an input file, computes the BAF (Basic Amplification Factor),
    and saves the results to an output file.

    Parameters:
    input_filename (str): The path to the input JSON file containing previous statistics.
    output_filename (str): The path to the output JSON file where computed BAF results will be saved.
    """
    with open(input_filename, 'r') as file:
        prev_stats = json.load(file)

    results = {}
    for ip, stats in list(prev_stats.items()):
        # Compute the BAF for the given IP based on the length of stats
        baf = len(stats) / 15
        results[ip] = {'stats': baf}

    # Write the computed BAF results to the output JSON file
    with open(output_filename, "w") as file:
        json.dump(results, file, indent=4)


def validate_server_response(packet, ip, port):
    """
    This function checks if a given network packet is a valid memcached response from a specified IP address.

    Parameters:
    packet (scapy.packet.Packet): The network packet to be checked.
    ip (str): The IP address expected to be the source of the memcached response.

    Returns:
    bool: True if the packet is a valid memcached response from the specified IP address, False otherwise.
    """
    # Check if the packet contains an IP layer and the source IP matches the specified IP address
    if IP in packet and packet[IP].src == ip:
        # Check if the packet contains a UDP layer and the source port is 11211 (memcached port)
        if UDP in packet and packet[UDP].sport == port:
            return True
    return False


if __name__ == "__main__":
    print('Packet sender...')
    if len(sys.argv) < 2:
        print("Usage: python packet_sender.py <method_name> <args>")
        sys.exit(1)

    method_name = sys.argv[1]
    args = sys.argv[2:]

    try:
        method = getattr(sys.modules[__name__], method_name)
    except AttributeError:
        print(f"Unknown method: {method_name}")
        sys.exit(1)

    method(*args)