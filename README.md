# Amplifier Detector

The repository contains the code used in my research project with title "Estimating the 
Amplification Factor in the Network Infrastructure of France".

## Use
The code is used to help network administrators or fellow researchers to identify amplifiers withing
network infrastructures. Amplifiers are vulnerable servers that return large responses
on small requests. 

The code should be used ethically without abusing the identified vulnerable servers. 

## Features
The code target mainly three protocols: DNS, NTP, and Memcached and implements the
following functionalities:
* Collect servers running a specific protocol using Censys API
* Find authoritative DNS servers in a country
* Determine whether a server is a potential amplifier by sending a simple UDP packet
* Compute the amplification factor by sending a UDP packet to the server

## Prerequisites

- Docker: Install Docker from [here](https://www.docker.com/get-started).
- Censys: Create an account [here](https://search.censys.io/) for the collection of servers
- IPinfo: Create an account [here](https://ipinfo.io/) to verify the location of the servers.

## Setup

1. Clone this repository and navigate to the project directory:
   ```sh
   git clone https://github.com/panayiotishad04/Amplifier-Collector.git
   cd <your-repository-name>
   ```
2. Add the credentials for Censys and IPinfo in the .env file
   ```python
   CENSYS_API_ID=add_censys_api_id
   CENSYS_API_SECRET=add_censys_api_secret_key
   IPINFO_API_KEY=add_ipinfo_api_key
   ```
3. Build the docker image 
   ```sh
   docker build -t <name_of_image> . 
   ``` 
3. Create an interactive image
   ```sh
   docker run -it <name_of_image> /bin/bash
   ```

## Step 1: Collecting Servers

### A. Censys
1. Change the query input in function e.g. "location.country_code: FR AND services.service_name: NTP AND services.port: 123"
   run ```python server_collection.py query_censys_and_save <query_input> <output_filename>```\
   ```<query_input>: Check censys search syntax``` \
   ```e.g., f"location.country_code: FR AND services.service_name: NTP AND services.port: 123"```
   


### B. Authoritative DNS 
1. Download files from https://toplists.net.in.tum.de/archive/ and add them to the docker container
2. Depending on the type of the file (csv or txt) use: \
run ```python server_collection.py extract_domain_names_csv <input_filename> <output_filename>```\
   or:\
   run ```python server_collection.py extract_domain_names_txt <input_filename> <output_filename>```

   Both methods add domain names to the output file if not present already, therefore
keeping only unique domain names.

## Step 2: Extract Open Servers
### A. Authoritative DNS
1. run ```python amplifier_discovery.py nameserver_collection <input_filename> <output_filename>``` to get 
authoritative DNS servers for the collected domain names

2. run ```python amplifier_discovery.py transform_reverse_dns_to_ip <input_filename> <output_filename>```  
This will resolve the reverse-DNS names from the previous step to get the 
IP addresses of the servers and extract only open servers.

3. run ```python amplifier_discovery.py extract_valid_geolocation <input_filename> <output_filename>``` to 
filter out servers not located in France

---
### B. Recursive DNS
run ```python amplifier_discovery.py filter_open_recursive_dns <input_filename> <output_filename>``` to 
collect open recursive DNS servers.

---
### C. NTP
run ```python amplifier_discovery.py filter_open_ntp_servers <input_filename> <output_filename>``` to 
collect open servers running NTP.
---

### D. Memcached
1. run ```python amplifier_discovery.py filter_open_memcached_servers <input_filename> <output_filename>```
to filter open Memcached servers by checking if they reply on UDP when asking for the
statistics of the server.

2. run ```python amplifier_discovery.py extract_memcached_servers_keys <input_filename> <output_filename>``` 
to extract keys from the open Memcached servers from the previous step.
- ```<output_filename>: e.g., memcached_keys.json```
---

## Step 3: Compute the Amplification Factor
### A. Authoritative DNS
run ```python packet_sender.py dns_experiment_authoritative <input_filename> <output_filename>```
- ```<input_filename>: output_filename in Step 2.A.3```
The default RR type parameter is ANY (255). You can try with another parameter by 
changing the value in the qtype parameter (e.g., qtype = 'TXT') when crafting the
packet in method ```measure_dns_authoritative_packet_size```.

---
### B. Recursive DNS
run ```python packet_sender.py dns_experiment_recursive <input_filename> <output_filename> <domain_name>``` 
- ```<input_filename>: output_filename in Step 2.B```
The default RR type parameter is ANY (255). You can try with another parameter by 
changing the value in the qtype parameter (e.g., qtype = 'TXT') when crafting the
packet in method ```measure_dns_authoritative_packet_size```.

---
### C. NTP 
run ```python packet_sender.py ntp_experiment <input_filename> <output_filename>```
- ```<input_filename>: file containing the keys obtained in Step 2.C```

---
### D. Memcached

### STATS
run ```python packet_sender.py compute_baf_for_stats <input_filename> <output_filename>```
- ```<input_filename>: file containing the statistics obtained in Step 2.B.1```

### Get key
run ```python packet_sender.py memcached_experiment <input_filename> <output_filename>```
- ```<input_filename>: file containing the keys obtained in Step 2.B.2```

---
## Step 4: Server Fingerprinting (Optional)
### Authoritative DNS
- run ```python server_fingerprinting.py collect_authoritative_dns_versions <input_filename> <output_filename>```
to get the server's version.

- run ```python server_fingerprinting.py collect_authoritative_buffer_sizes <input_filename> <output_filename>```
to get the server's buffer size.

---
### Recursive DNS
- run ```python server_fingerprinting.py collect_recursive_dns_versions <input_filename> <output_filename>```
to get the server's version .

- run ```python server_fingerprinting.py collect_recursive_buffer_sizes <input_filename> <output_filename>```
to get the server's buffer size.

---
### NTP
run ```python server_fingerprinting.py collect_ntp_versions <input_filename> <output_filename>``` to ge the
version of NTP servers with ntpq.

---
### Memcached
run ```python server_fingerprinting.py collect_memcached_versions <input_filename> <output_filename>``` to
get version of Memcached servers over TCP.
