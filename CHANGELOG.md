# Implemented functionality
 - Command line parameter parser
    - Base parameters 
    - Help parameter
 - Fetch device interface(s) function
   - Active interface list display
 - DNS query to get host (destination) ip address(es)
 - Fetch interface (source) address function
 - Scanner setup procedure
 - Port list processing
 - Port scan
   - Packet assembly
     - Pseudo IPv4, IPv6 headers
     - Checksum
     - Create protocol headers
     - Create IP headers (unused)
     - Hex dump packet content (debugging)
   - Await response
   - Packet filter
   - Extract packet data
     - Evaluate port state 
 - Additional features
   - Verbose - displays additional information during the scan process
   - Resend - Maximum retries of packet transmission
   - Rate limit - Rate limit for sending UDP packets

# Issues
If the interface is other than 'lo' and the scanned device is localhost,
no response is received on the socket, although the probe packet is sent
and the corresponding response is received back (can be seen in wireshark or tcpdump).
Temporarily solved by a condition in the scan.h file.