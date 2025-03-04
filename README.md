
# IPK25 Project 1 - OMEGA: L4 Scanner

Simple TCP and UDP network L4 scanner for *Linux*, implemented in *C* programming language.

#### Author

- [@Marek Pazúr (xpazurm00)](https://www.github.com/0x6b6)

### Content structure
- [Documentation](#documentation)
   - [Theory](#theory)
     - [L4 network scanning](#l4-network-scanning)
     - [TCP SYN Scan](#tcp-syn-Scan)
     - [UDP ICMP Scan](#udp-icmp-port-unreachable-scanning)
     - [Checksum](#checksum)
     - [Pseudo headers](#pseudo-headers)
   - [Implementation details](#implementation-details)
     - [Parameter parsing](#parameter-parsing)
     - [Scanning](#scanning)
     - [Network and utilities](#network-and-utilities)
     - [Compilation](#compilation)
   - [Testing](#testing)
     - [Testing devices](#testing-devices)
     - [Testing environment](#testing-environment)
     - [Testing tools used](#testing-tools-used)
     - [Test cases](#test-cases)
- [Execution](#execution)
   - [Parameter specification](#parameter-specification)
- [Additional features](#additional-features)
- [License](#license)
- [Bibliography](#bibliography)
## Documentation
This document includes
- Executive summary of the theory necessary to understand the functionality of the implemented application
- Implementation details
- Testing details

## Theory

### L4 network scanning
Port scanning is a method for discovering useful communication channels on a host. The core idea is to probe as many ports as possible, ideally while remaining undetected, and track which ports are open or closed.

The port scan process involves sending requests to a range of server port addresses to identify receptive ports and determine the available services on the target machine.

There are many port scanning methods, in this project, the TCP SYN scan and UDP scan methods are specifically used, which will be described later on.

The responses can be classified in three categories
- open
- closed
- filtered

### TCP SYN Scan
Also referred to as "half-open" scanning, as this method simulates the three-way handshake of the reliable TCP protocol without fully completing it.

The *advantages* of this method are that it is relatively lightweight and can be performed quickly on a fast network without firewall bottlenecks. Most importantly, it is stealthy, as it does not complete the full handshake, making detection more difficult.

First step to initiate a *three-way handshake* is to create a TCP packet with the *SYN* flag set and send it to the target host to scan the desired port(s).

Now there are three options of whats about to happen in the second step
- Target host sends a response with *SYN, ACK* flags set back
- Target host sends a response with *RST* flags set back
- No response is received

Since this method is using the TCP protocol, it is much easier to evaluate the port status.

If the host responds with *SYN-ACK*, the port is confirmed to be open for communication.

Normally, the last step would be to send a *RST* flag set packet to terminate the connection with the target host, since it would keep sending the SYN-ACK response. However, this step is unnecessary, as the operating system kernel automatically sends an RST packet when it receives an unexpected SYN-ACK response.

![TCP SYN ACK](images/tcp_syn_ack.png)

In conclusion, the port is classified as **OPEN**.

![TCP RST ACK](images/tcp_rst_ack.png)

If the host responds with *RST*, the port is confirmed to be **CLOSED**.

![Retransmission](images/tcp_resend.png)

If no response is received, it may indicate packet loss, so the *TCP SYN* packet is retransmitted an arbitrary number of times.

![Timeout](images/tcp_timeout.png)

If there is still no response, the port is finally classified as **FILTERED**.


### UDP ICMP port unreachable scanning

While the UDP protocol itself is rather simple, the UDP scanning proccess is more difficult when evaluating probed ports state, since the ports are not obliged to send either a acknowledgement or an error response. Only way to achieve evaluation of scanned ports, is to rely on the target host sending an *error ICMP* packet of type ICMP_PORT_UNREACH. This helps to figure out if a port is **CLOSED**, and by exclusion determine which ports are not.

![UDP ICMP](images/udp_icmp.png)

The main *disadvantage* of this method is that the UDP protocol is *less reliable* than TCP, and probe packets may fail to reach the target host.
To mitigate this, probe packets should be retransmitted to increase the chances of receiving a response, especially if packet loss is suspected. Another challenge is *rate limiting*, as some hosts restrict the rate of ICMP error responses.

In conclusion, this method may *fail* to accurately classify port states and *is generally slower*.

### Checksum
Checksum is a simple, generic algorithm thats serves a purpose of verifying data integrity.

The principle of the algorithm is a 16-bit ones complement sum ensuring data integrity. If the data length is odd, padding is added (but not transmitted) for alignment. The checksum also includes a **pseudo-header** for additional verification to protect against misrouted segments.

It prevents corrupted data being delivered, and to do so the sender **MUST** generate it and the receiver **MUST** check it. 

To send probe packets to scan ports, they **MUST** be include the checksum in the protocol headers.

### Pseudo headers
IPv4 (96 bits) and IPv6 (320 bits) pseudo-headers primarily contain the source address of the sender and the destination address of the target host, providing additional protection against misrouted segments.

## Implementation details
The program consists of the following source files (located in /src)
- `main.c` Program entry point.
- `net_utils.c` `net_utils.h` Network and utility functions.
- `opts.c` `opts.h` Parameter parsing.
- `scan.c` `scan.h` Port scanning process.
- `Makefile`

where the .h (header files) contain necessary function interfaces.

*Note*: Description is also available in the aforementioned source files.

### Parameter parsing
This section uses `opts.c`, `opts.h` modules to parse command line parameters and prepare the configuration of the program.

#### Configuration structure
```c
typedef struct config {
	char *interface;        // Device interace
	struct ifaddrs *ifaddr; // Interface adress(es) information

	ports_t tcp_ports;
	ports_t udp_ports;

	unsigned int timeout;    // Response timeout
	unsigned int rate_limit; // Rate limit for UDP scanning
	unsigned int retry;      // Number of times a packet should be resent in case of no response

	char *dn_ip;            // Domain name | IP address
	char addr_str[64];      // Buffer of 64 bytes should be enough for any address in ASCII string format

	uint8_t verbose;        // Show details
} cfg_t;
```
List of parsing functions and macros in `opts.c`, `opts.h`:
 - `init_cfg`: Initialises the cfg_t structure
 - `free_cfg`: Releases resources used by cfg_t structure
 - `parse_opt`: Parses specified command line arguments and sets the cfg_t structure accordingly
 - `parse_ports`: Parses various port selection formats 
 - `parse_number`: Parses integers in decimal format
 - `CHECK_PARAM`: Evaluates if a parameter is valid

*Note*: Only `init_cfg`, `free_cfg`, `parse_opt` function interfaces are available to use outside `opts.c`.

#### Parsing
Parameters are parsed by the `parse_opt` function, which iterates through all specified parameters and these are then processed
by other auxiliary functions such as `is_opt`, `parse_ports`, `parse_number` or the `CHECK_PARAM macro`.

At the same time, duplicate parameters, allowed values ​​and ranges, port selection format and specification of required parameters are checked.

The result is an initialized `cfg_t` structure, which determines the conditions of the port scanning process.

### Scanning
This section uses `scan.c`, `scan.h`, `net_utils.h` modules to process data and use essential network functions/utilities to perform port scanning.


#### Scanner structure
```c
typedef struct l4_scanner {
	int socket_fd;                      // Socket file descriptor

	uint16_t source_port;               // Source port (randomized)
	uint16_t destination_port;          // Destination port (selected by input)

	sa_family_t family;                 // Address family (IPv4/IPv6)

	struct sockaddr *source_addr;       // Source address (selected interface)
	struct sockaddr *destination_addr;  // Destination address (derived from host(s) address or domain name)

	socklen_t source_addr_len;          // Source addres length
	socklen_t destination_addr_len;     // Destination address length
} l4_scanner;
```

The entire scanning proccess is defined by these functions in `scan.c`, `scan.h`:
- `start_scan`: Prepares essential data required to start scanning
- `set_scanner`: Initialises the *l4_scanner* struct with the collected data
- `process_ports`: Processes *ports_t* structure and creates a raw socket according to the TCP/UDP protocol 
- `port_scan`: Performs the TCP SYN and the UDP ICMP scans 

#### Starting scan
Before starting the port scan, the IP addresses of both the host and the client must be retrieved.

A DNS query is made using the `getaddrinfo` function to obtain a list of IPv4 and IPv6 addresses for the specified host, which can either be a domain name or a raw IP address. A while loop iterates through the list to ensure that every IP address associated with the host is scanned.

Next, the device interface source address is fetched using the `get_ifaddr` function, based on the IP address family and specified parameters. Specifically, if the host IP address is IPv4, the interface address will also be IPv4, and vice versa.

Once the data is collected, the scanner structure is initialized using the `set_scanner` function, and the *port structures* are prepared for processing, separately for the TCP and UDP protocols.

![Start scan diagram](images/diagram_start_scan_white.png)

#### Port processing
Both *TCP* and *UDP* *port structures* are iterated through using for loops. It is distinguished whether it is a *range* or a *list*.

```c
typedef struct ports {
	unsigned int access_type; // Either a range or a list

	struct range {
		unsigned int from;
		unsigned int to;
	} range;

	unsigned int *port_list;
	size_t list_length;
	size_t list_capacity;
} ports_t;
```
In order to create and be able to send custom protocol packets, a raw socket with the specified protocol (TCP or UDP) must be created using function `create_socket` and bound to the chosen interface. Additionally, the communication of the sockets is set to be **non-blocking network I/O**, since polling will be used later on to wait for responses.

![Process ports diagram](images/diagram_process_ports_white.png)

#### Port scanning
At this stage, the port scanning process begins. However, a few preparations are required, such as assembling the packet to be sent and setting up the response socket.

`Packet assembly` is responsible for constructing the protocol packet. This function follows a structured pipeline where the protocol header is created, configured (addressing, checksum, etc.), and then encapsulated within an IP header.

**Important**: Custom IP header creation is not used, as the operating system automatically generates one. However, if needed, it can be manually created using the create_iphdr function.

If the current protocol is `TCP`
- A packet with TCP header and the *SYN, ACK* flags set is created.
- The response socket is set to the already created raw socket since a TCP response is expected.
- The custom TCP probe packet is sent using the TCP raw socket.

If the current protocol is `UDP`
- A packet with UDP header is created.
- Response receive socket is set to a new socket, created using mentioned `create_socket` function, with ICMP or ICMPV6 as the protocol type, since ICMP response is expected.
- Custom UDP probe packet is sent using the UDP raw socket.

Finally, the scanner waits for a response using `poll` function.

Since packet loss can occur at any time, the probe packet may not reach the target, resulting in no response. Depending on the `--resend` parameter, the probe packet will be resent a specified number of times before classifying the port as filtered (*for TCP*) or open (*for UDP*).

If a response packet arrives, it is first filtered through the `filter_addresses` function before being passed to `extract_data` for evaluation. 

![Port scan diagram](images/diagram_port_scan_white.png)

Depending on the protocol, the corresponding protocol head is extracted from the packet and filtered through the `filter_ports` function. 

Finally, the port state is classified:

If the current protocol is `TCP`
- Response packet has SYN-ACK flags → port is **OPEN**
- Response packet has RST-ACK flags → port is **CLOSED**
- Otherwise port is **FILTERED**

If the current protocol is `UDP`
- Response ICMP(V6) packet has type ICMP_DEST_UNREACH and code ICMP_PORT_UNREACH → port is **CLOSED**
- Otherwise port is **OPENED**

### Network and utilities
This section describes `net_utils.c`, `net_utils.h` modules containing essential network and utility functions used by the scan process.

List of important function interfaces in `net_utils.h`:
- `get_interfaces`: Fetches interface(s) list.
- `get_ifaddr`: Fetches specified interface source address.
- `addr_to_string`: Converts IPv4/IPv6/MAC adresses from binary to ASCII string.
- `list_interfaces`: Prints active interfaces with their address and state.
- `create_socket`: Creates a raw socket bound to interface and protocol.
- `close_socket_fd`: Closes socket file descriptors.
- `create_prot_header`: Creates a TCP/UDP header.
- `create_prot_header`, `create_pseudo_ipv6_h`: Creates a pseudo IPv4/IPv6 header structure to be later used in checksum.
- `calculate_checksum`: Calculates checksum of given data.
- `create_iphdr`: Creates IPv4/IPv6 header. Ready to be used, but is **not** currently used in the project.
- `packet_assembly`: Creates a TCP/UDP packet ready to be sent.
- `filter_addresses`: Filters out misrouted packets by addressess.
- `filter_ports`: Filters out misrouted packets by ports.
- `extract_data`: Extracts data from response and evaluates port state.

List of auxiliary private functions defined in `net_utils.c`:
- `service`: Prints service of a port by protocol.
- `rate_limit`: Rate limit setting for UDP scanning.
- `hexdump_packet`: Prints the content of a packet in hexadecimal format.
- `print_if_flags`: Prints the status of the interface.




### Compilation

The program is compiled using the **GCC** compiler with the following flags:

```bash
gcc -std=c17 -Wall -Wextra -Werror -D_GNU_SOURCE -Wpedantic
```
## Testing

#### Testing devices
- Desktop PC with ethernet cable connection (eth0, ens33)
- Laptop with wireless connection (wlo1)

#### Testing environment
- OS: Ubuntu 22.04.5 LTS x86_64, Kernel: 6.8.0-52-generic
- OS: Ubuntu 24.04.2 LTS, x86_64
- OS: Ubuntu 24.04 LTS, amd64 (reference virtual machine IPK25_Ubuntu24.ova)

#### Testing tools used
- nmap
- netcat
- wireshark
- ping
- ping6
- valgrind
- lsof

#### Test cases
- Port scan correct evaluation
- Parameter parsing
- Memory leaks & file descriptor handling

what was tested

why it was tested

how it was tested

what were the inputs, expected outputs, and actual outputs


## Execution
*Root privileges are required in order to scan ports.*

Go to source file directory

```bash
  cd ./src
```

Build via make

```bash
  make all
```

Execute the scanner with root privileges

```bash
  sudo ./ipk-l4-scan [-i interface | --interface interface] [--pu port-ranges | --pt port-ranges | -u port-ranges | -t port-ranges] {-w timeout} [domain-name | ip-address]
  {-r resend} {-l rate-limit} {-v verbose}
```
### Parameter specification (arguments)

| Parameter              | Information                               | Allowed values | Default    |
| ---------------------- | ----------------------------------------- | -------------- | ---------- |
|  `-i`, `--interface`   | Device interface (source address)         | Interface name | (Required) |
|  `-t`, `--pt`          | Selection of TCP ports to be scanned      | 1-65535        | (Required) |
|  `-u`, `--pu`          | Selection of UDP ports to be scanned      | 1-65535        | (Required) |
|  `-w`, `--timeout`     | Timeout for target host response [ms]     | 0-UINT max     | `5000 ms`  |
|  `-r`, `--resend`      | Maximum retries of packet transmission    | 0-UINT max     | `1 retry`  |
|  `-l`, `--ratelimit`   | Rate limit for sending UDP packets [ms]   | 0-UINT max     |  `1000 ms` |
|  `-v`, `--verbose`     | Show additional information during scan   | N/A            | N/A        |
|  `-h`, `--help`        | Show help message                         | N/A            | N/A        |

#### Recomendations
- `--interface` It is advisable to select the correct interface and check if it supports IPv4 or IPv6 addressing, if necessary.
- `--timeout` A higher value may improve scan accuracy, but at the expense of speed.
- `--verbose` Useful for debugging or when detailed information is needed
- `--ratelimit` The default value is set to 1000 milliseconds, as many hosts rate-limit ICMP port unreachable messages. The Linux kernel typically limits ICMP destination unreachable messages to one per second, so it **should not** be modified if uncertain.
- `--resend` Increases the likelihood of receiving a response, as packet loss may occur.

#### Port selection formating
- `x-y` Basic range format (e.g. 80-443)

- `x to y`, `x to `, `to y`  Extended range format:  if one side is blank, it is implicitly treated as the minimum (1) or maximum (65535) of the port range (e.g. 80 to 443; 65350 to; to 80)

- `x`, `x,y,z` Basic list format (e.g. 80, 443, 8080)

*Restrictions*: Selected ports must lie within the range 1-65535. In the case of a range format, the lower limit must not exceed the upper limit, and vice versa.

#### Examples

- Basic functionality
```bash
  sudo ./ipk-l4-scan -i eth0 --pt 80,443 --pu 53-67 www.scanme.org
```
- Extended functionality
```bash
  sudo ./ipk-l4-scan -i wlo1 -t 80to443 -u to67 www.scanme.org -w 1000 -v
```

```bash
  sudo ./ipk-l4-scan www.scanme.org --interface ens33 --pt "53, 80, 443" --pu "21 to 24" --timeout 1000 --ratelimit 100 --resend 2 -v
```

- Display active interface(s)
```bash
  sudo ./ipk-l4-scan -i
```
## Additional Features

- Extended port parsing: 'to', whitespace skip
- Verbose
- Rate limiting
- Transmission retries


## License

This project is licensed under the [GNU GPL-3.0](https://www.gnu.org/licenses/gpl-3.0.html)


## Bibliography

- [1] https://en.wikipedia.org/w/index.php?title=Port_scanner&oldid=1225200572

- [2] https://nmap.org/nmap_doc

- [3] https://nmap.org/book/scan-methods-udp-scan.html

- [4] https://nmap.org/book/synscan.html

- [5] RFC 793: https://datatracker.ietf.org/doc/html/rfc793

- [6] RFC 768: https://datatracker.ietf.org/doc/html/rfc768

- [7] RFC 1071: https://datatracker.ietf.org/doc/html/rfc1071

- [8] RFC 791: https://datatracker.ietf.org/doc/html/rfc791#section-3.1

- [9] RFC 1812: https://datatracker.ietf.org/doc/html/rfc1812#section-4.3.2.8

- [10] RFC 9293: https://datatracker.ietf.org/doc/html/rfc9293

- [11] https://git.fit.vutbr.cz/NESFIT/IPK-Projects/src/branch/master#documentation-instructions

- [12] https://git.fit.vutbr.cz/NESFIT/IPK-Projects/src/branch/master/Project_1/omega
