# IPK L4 Scanner

A network port scanner implementation in C# that supports both TCP and UDP scanning for IPv4 and IPv6 networks.

## Theory

### TCP Scanning (SYN Scan)

TCP SYN scanning is a stealthy port scanning technique that works by sending a SYN packet to the target port and analyzing the response:

1. **Open Port**: If the port is open, the target responds with a SYN-ACK packet
2. **Closed Port**: If the port is closed, the target responds with a RST packet
3. **Filtered Port**: If no response is received (timeout) or an ICMP error is received, the port is considered filtered

The scanner uses raw sockets to construct and send TCP packets manually, allowing for more control over the scanning process and avoiding detection by some security systems.

### UDP Scanning

UDP scanning works by sending empty UDP packets to target ports and analyzing the responses:

1. **Open Port**: If no response is received (timeout), the port is considered open
2. **Closed Port**: If an ICMP Port Unreachable message is received, the port is closed

UDP scanning is more challenging than TCP scanning because:

- UDP is connectionless
- Many firewalls block ICMP messages
- UDP responses are not guaranteed

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

![Class Diagram](class-diagram.png)

## Usage

### Prerequisites

- .NET 9.0 SDK or later
- Linux operating system (for raw socket support)
- Root/sudo privileges (required for raw socket operations)

### Building

```bash
dotnet build
```

### Running

The program requires sudo privileges due to raw socket usage:

```bash
sudo dotnet run [options] target
```

### Command Line Arguments

```
./ipk-l4-scan {-h} [-i interface | --interface interface]
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

For testing, I used wireshark to capture the packets and to see the responses. I also used nmap to compare the results.

TODO: Add testing, some wireshark captures would be nice, and nmap scans for comparison

## Bibliography

1. Stevens, W. R. (1994). TCP/IP Illustrated, Volume 1: The Protocols. Addison-Wesley.
2. Postel, J. (1981). Transmission Control Protocol. RFC 793.
3. Postel, J. (1980). User Datagram Protocol. RFC 768.
