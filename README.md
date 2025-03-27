# IPK L4 Scanner

A network port scanner implementation in C# that supports both TCP and UDP scanning for IPv4 and IPv6 networks.

## Theory

Port scanning is a technique used to discover which ports on a network host are open, closed, or filtered. It is a crucial tool in network security assessment and system administration, helping to:

1. Identify potential security vulnerabilities
2. Verify firewall configurations
3. Monitor network services
4. Detect unauthorized services

The process involves sending specially crafted packets to target ports and analyzing the responses. Different scanning techniques exist, with TCP SYN scanning and UDP scanning being among the most common.

### TCP Scanning (SYN Scan)

SYN scanning is the most commonly used and default scanning method, primarily due to its speed and efficiency. It allows scanning thousands of ports per second on a fast network, provided there are no restrictive firewalls in place. Additionally, it remains relatively stealthy since it does not establish full TCP connections.

This method is often called **half-open scanning** because a full TCP handshake is never completed. Instead, a SYN packet is sent as if initiating a connection, and the response is observed.

- A **SYN/ACK** response indicates that the port is **open (listening)**.
- A **RST (reset)** response signifies that the port is **closed (non-listening)**.
- If no response is received after multiple retries, the port is classified as **filtered**.
- If an **ICMP unreachable error** (type 3, code 0, 1, 2, 3, 9, 10, or 13) is received, the port is also marked as **filtered**.
- In rare cases, if a **SYN packet (without the ACK flag)** is received in response, the port is considered **open**. This may occur due to an uncommon TCP behavior known as **simultaneous open** or **split handshake connection**.

### UDP Scanning

While TCP powers most major Internet services, **UDP-based services** are also widely used. Common examples include **DNS, SNMP, and DHCP**, which operate on ports **53, 161/162, and 67/68**, respectively. Since **UDP scanning is slower and more challenging** than TCP scanning, some security auditors tend to overlook these ports.

A UDP scan sends **UDP packets** to the target ports. Usually, these packets are **empty**, but for certain well-known ports, a **protocol-specific payload** is used. Based on the response (or absence of one), ports are classified as:

- **Open:** If any UDP response is received (this is rare).
- **Open | Filtered:** If no response is received, even after multiple retransmissions.
- **Closed:** If an **ICMP port unreachable error** (type 3, code 3) is returned.
- **Filtered:** If other ICMP unreachable errors (type 3, codes 1, 2, 9, 10, or 13) are received.

## Implementation

The program starts by parsing provided arguments and validating them. Then it gets all the IP addresses for the provided interface. After that, it resolves the target address or addresses if hostname was provided. It loops through all the addresses and scans the ports.

### TCP Scanning

For TCP scanning, the program uses the `TcpScanner` class. It builds a TCP SYN packet and sends it to the target port using raw socket. It then waits for the response and analyzes it. If the response is a SYN-ACK, the port is considered open. If the response is a RST, the port is considered closed. Otherwise, it sends the packet again and if it doesn't receive a response, the port is considered filtered.

### UDP Scanning

UDP scanning is implemented in the `UdpScanner` class. It builds an empty UDP packet and sends it to the target port using raw socket. It then waits for the response and analyzes it. If the response is an ICMP Port Unreachable message (type 3, code 3), the port is considered closed. Otherwise, it sends the packet again and if it doesn't receive a response, the port is considered open.

### Core Classes

- `Program.cs`: Main entry point, handles program flow
- `ArgumentParser.cs`: Parses command-line arguments
- `Scanner.cs`: Interface defining the scanning contract
- `TcpScanner.cs`: Implements TCP SYN scanning
- `UdpScanner.cs`: Implements UDP scanning

![Class Diagram](screenshots/class-diagram.png)

## Usage

### Prerequisites

- .NET 9.0 SDK or later
- Linux operating system (for raw socket support)
- Root/sudo privileges (required for raw socket operations)

### Building

```bash
make
```

### Running

The program requires sudo privileges due to raw socket usage:

```
sudo ./ipk-l4-scan {-h} [-i interface | --interface interface]
              [--pu port-ranges | --pt port-ranges | -u port-ranges | -t port-ranges]
              {-w timeout} [hostname | ip-address]
```

Options:

- `-h, --help`: Display help message
- `-i, --interface`: Select network interface
- `-t, --pt`: TCP ports to scan (1,2,3 or 1-1024)
- `-u, --pu`: UDP ports to scan (1,2,3 or 1-1024)
- `-w, --wait`: Timeout in milliseconds (default: 5000)

### Examples

1. List available interfaces:

```bash
sudo dotnet run
```

2. TCP scan of ports 80 and 443:

```bash
sudo dotnet run -i eth0 -t 80,443 example.com
```

3. UDP scan of ports 53 and 123:

```bash
sudo dotnet run -i eth0 -u 53,123 example.com
```

4. Scan port range:

```bash
sudo dotnet run -i eth0 -t 1-1024 example.com
```

5. Combined TCP and UDP scan with custom timeout:

```bash
sudo dotnet run -i eth0 -t 80,443 -u 53 -w 1000 example.com
```

## Testing

For testing, I used `wireshark` to capture the packets and to see the responses. I also used `nmap` to compare the results. Also, the school `VPN` was used to test the IPv6 scanning, because the IPv6 is not working on my home network :(.

1. Show all interfaces:

```bash
sudo dotnet run
```

![All interfaces](screenshots/all_interfaces.png)

2. Arguments tests, basically i tested some wrong arguments to see if the program handles them correctly:

![Arguments tests](screenshots/arguments_test.png)

3. Scanning TCP and UDP ports 80, 443 on scanme.nmap.org using the school VPN (IPv6). The results are compared with wireshark captures and nmap scan.

```bash
sudo ./ipk-l4-scan -i tun0 -t 80,443 scanme.nmap.org
```

![TCP and UDP scan](screenshots/hostname_ipv6_ipv4_test.png)

4. Scanning filtered ports, to test if the program double sends the packets. The result is compared with wireshark captures and nmap scan.

```bash
sudo ./ipk-l4-scan -i enp2s0 -t 23 147.229.9.23
```

![Filtered ports](screenshots/filtered_test.png)

## Bibliography

1. Stevens, W. R. (1994). TCP/IP Illustrated, Volume 1: The Protocols. Addison-Wesley.
2. Postel, J. (1981). Transmission Control Protocol. RFC 793.
3. Postel, J. (1980). User Datagram Protocol. RFC 768.
4. [Wireshark](https://www.wireshark.org/docs/)
5. [Nmap](https://nmap.org/book/man.html)
