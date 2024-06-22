from censys.search import CensysHosts
from scapy.layers.dns import DNS, DNSQR, DNSRROPT
import json
from scapy.all import *
from scapy.layers.inet import IP, UDP
from pymemcache.client.base import Client
from packet_sender import validate_server_response


def get_buffer_size_dns(dns_server, domain_name):
    """
    This function sends a DNS query to a specified DNS server and attempts to determine the buffer size
    by analyzing the DNS response.

    Parameters:
    dns_server (str): The IP address of the DNS server.
    domain_name (str): The domain name to query.

    Returns:
    int/str: The buffer size if found, otherwise 'Not known'.
    """
    # Craft DNS query packet
    dns_request = IP(dst=dns_server) / UDP(sport=RandShort(), dport=53) / DNS(ad=1,
                                                                              qd=DNSQR(qname=domain_name, qtype='A'),
                                                                              ar=DNSRROPT(rclass=4096, z=1))

    # Send the DNS query
    send(dns_request, verbose=0)

    # Sniff responses and validate them
    responses = sniff(lfilter=lambda x: validate_server_response(x, dns_server, 53), timeout=2)

    # Analyze the responses to find the buffer size
    for response in responses:
        if response[DNS].arcount > 0:
            for i in range(response[DNS].arcount):
                ar_record = response[DNS].ar[i]
                if ar_record.type == 41:  # Check if the record type is OPT (EDNS0)
                    buffer_size = ar_record.rclass
                    print(buffer_size)
                    return buffer_size

    return 'Not known'


def get_dns_version(domain):
    """
    This function uses the fpdns tool to determine the DNS software version running on a server.

    Parameters:
    domain (str): The domain name or IP address of the DNS server.

    Returns:
    str: The DNS server fingerprint if found, otherwise 'Not known'.
    """
    command = f"fpdns -p 53 -t 3 {domain}"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()

    if process.returncode == 0:
        # Successful execution
        fingerprint = output.decode("utf-8").split(': ')[1].strip()
        return fingerprint
    else:
        # Error occurred
        print("Error:", error.decode("utf-8"))
        return 'Not known'


def collect_authoritative_dns_versions(input_filename, output_filename):
    """
    This function reads a list of authoritative DNS servers from an input file, determines the DNS software version
    for each server using fpdns, and saves the results to an output file.

    Parameters:
    input_filename (str): The path to the input JSON file containing authoritative DNS servers.
    output_filename (str): The path to the output JSON file where results will be saved.
    """
    with open(input_filename, 'r') as file:
        authoritative_dns = json.load(file)

    results = {}
    for ip in authoritative_dns.keys():
        results[ip] = get_dns_version(ip)

    # Write the results to the output JSON file
    with open(output_filename, "w") as file:
        json.dump(results, file, indent=4)


def collect_authoritative_buffer_sizes(input_filename, output_filename):
    """
    This function reads a list of authoritative DNS servers from an input file, determines the buffer size
    for each server, and saves the results to an output file.

    Parameters:
    input_filename (str): The path to the input JSON file containing authoritative DNS servers.
    output_filename (str): The path to the output JSON file where results will be saved.
    """
    with open(input_filename, 'r') as file:
        authoritative_dns = json.load(file)

    results = {}
    for ip, domains in authoritative_dns.items():
        results[ip] = get_buffer_size_dns(ip, domains[0])

    # Write the results to the output JSON file
    with open(output_filename, "w") as file:
        json.dump(results, file, indent=4)


def collect_recursive_dns_versions(input_filename, output_filename):
    """
    This function reads a list of recursive DNS servers from an input file, determines the DNS software version
    for each server using fpdns, and saves the results to an output file.

    Parameters:
    input_filename (str): The path to the input JSON file containing recursive DNS servers.
    output_filename (str): The path to the output JSON file where results will be saved.
    """
    with open(input_filename, 'r') as file:
        authoritative_dns = json.load(file)

    results = {}
    for server in authoritative_dns:
        ip = server['ip']
        results[ip] = get_dns_version(ip)

    # Write the results to the output JSON file
    with open(output_filename, "w") as file:
        json.dump(results, file, indent=4)


def collect_recursive_buffer_sizes(input_filename, output_filename):
    """
    This function reads a list of recursive DNS servers from an input file, determines the buffer size
    for each server, and saves the results to an output file, updating it with any new findings.

    Parameters:
    input_filename (str): The path to the input JSON file containing recursive DNS servers.
    output_filename (str): The path to the output JSON file where results will be saved.
    """
    with open(input_filename, 'r') as file:
        recursive_dns = json.load(file)

    results = {}
    for server in recursive_dns:
        ip = server['ip']
        results[ip] = get_buffer_size_dns(ip, 'google.com')


    # Write the updated buffer sizes to the output JSON file
    with open(output_filename, "w") as file:
        json.dump(results, file, indent=4)


def get_ntp_version(ntp_server):
    """
    Retrieve the NTP version from a specified NTP server using ntpq.

    Args:
        ntp_server (str): The IP address or hostname of the NTP server to be queried.

    Returns:
        str: The NTP version information if found, otherwise 'Not known'.
    """
    try:
        # Run the ntpq command to get the remote variables
        result = subprocess.run(
            ['ntpq', '-c', 'rv', f'{ntp_server}'],
            capture_output=True,
            text=True,
            timeout=3
        )

        # Check if the command was successful
        if result.returncode != 0:
            print(f"Error querying NTP server {ntp_server}: {result.stderr}")
            return 'Not known'

        # Parse the output to find the version
        output = result.stdout
        version_line = None

        for line in output.split('\n'):
            if 'version' in line:
                version_line = line
                break

        if version_line:
            # Extract the version information
            version_info = version_line.split('=')[1].strip()
            print(f"Extracted version information: {version_info}")
            return version_info
        else:
            print(f"Version information not found in response from {ntp_server}")
            return 'Not known'

    except Exception as e:
        print(f"Exception occurred while querying NTP server {ntp_server}: {str(e)}")
        return 'Not known'


def collect_ntp_versions(input_filename, output_filename):
    """
    This function reads a list of NTP servers from an input file, retrieves the NTP version
    for each server, and saves the results to an output file.

    Parameters:
    input_filename (str): The path to the input JSON file containing NTP servers.
    output_filename (str): The path to the output JSON file where results will be saved.
    """
    with open(input_filename, 'r') as file:
        ntp_servers = json.load(file)

    results = {}
    for server in ntp_servers[:5]:
        ip = server['ip']
        results[ip] = get_ntp_version(ip)

    # Write the results to the output JSON file
    with open(output_filename, 'w') as file:
        json.dump(results, file, indent=4)


def get_memcached_version(memcached_server):
    """
    This function retrieves the version of a memcached server.

    Parameters:
    memcached_server (str): The IP address of the memcached server.

    Returns:
    str: The version of the memcached server if found, otherwise 'Not known'.
    """
    try:
        # Create a Memcached client
        mc = Client((memcached_server, 11211), connect_timeout=3, timeout=3)

        # Send the 'version' command to retrieve the version
        version = mc.version()
        parsed_version = str(version).split('b')[1][1:-1]
        return parsed_version
    except:
        return 'Not known'


def collect_memcached_versions(input_filename, output_filename):
    """
    This function reads a list of memcached servers from an input file, retrieves the version
    for each server, and saves the results to an output file.

    Parameters:
    input_filename (str): The path to the input JSON file containing memcached servers.
    output_filename (str): The path to the output JSON file where results will be saved.
    """
    with open(input_filename, "r") as file:
        memcached_servers = json.load(file)

    results = {}
    for server in memcached_servers:
        ip = server['ip']
        version = get_memcached_version(ip)
        results[ip] = version

    # Write the updated dictionary to the output JSON file
    with open(output_filename, "w") as file:
        json.dump(results, file, indent=4)


def query_censys_per_ip(input_filename, output_filename):
    """
    This function reads a list of DNS servers from an input file, performs a search query on Censys
    for each server's IP, and saves the results to an output file.

    Parameters:
    input_filename (str): The path to the input JSON file containing DNS servers.
    output_filename (str): The path to the output JSON file where results will be saved.
    """
    with open(input_filename, 'r') as file:
        dns_servers = json.load(file)

    # Initialize CensysHosts object
    h = CensysHosts()

    with open(output_filename, 'r') as file:
        results = json.load(file)

    for ip in dns_servers.keys():
        time.sleep(1.5)  # Rate limiting
        # Perform the search query on Censys for the given IP
        query = h.search(ip)

        # Retrieve the query results
        query_result = query()
        print(query_result)
        if len(query_result) > 0:
            results.append(query_result[0])
        else:
            results.append({'ip': ip, 'error': 'Could not find info'})

    # Write the query results to the output JSON file
    with open(output_filename, "w") as outfile:
        outfile.write(json.dumps(results, indent=4))

    print(f"Query results have been saved to {output_filename}")


if __name__ == "__main__":
    print('Server fingerprinting...')
    if len(sys.argv) < 2:
        print("Usage: python server_fingerprinting.py <method_name> <args>")
        sys.exit(1)

    method_name = sys.argv[1]
    args = sys.argv[2:]

    try:
        method = getattr(sys.modules[__name__], method_name)
    except AttributeError:
        print(f"Unknown method: {method_name}")
        sys.exit(1)

    method(*args)