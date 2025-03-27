using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Linq;
using System.Net.NetworkInformation;

class UdpScanner : Scanner
{
    private IPAddress _localAddress;

    public UdpScanner(IPAddress localAddress)
    {
        _localAddress = localAddress;
    }

    public async Task ScanPorts(IPAddress address, List<int> ports, int timeout)
    {
        bool isIpv6 = address.AddressFamily == AddressFamily.InterNetworkV6;
        foreach (var port in ports)
        {
            var result = isIpv6 ?
                await UdpScanIpv6(address, port, timeout) :
                await UdpScan(address, port, timeout);
            Console.WriteLine($"{address} {port} udp {result}");
        }
    }

    private async Task<string> UdpScanIpv6(IPAddress address, int port, int timeout)
    {
        // Create UDP socket for sending
        using Socket udpSocket = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
        udpSocket.Bind(new IPEndPoint(_localAddress, 0));

        // Create ICMPv6 socket for receiving port unreachable messages
        using Socket icmpSocket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IcmpV6);
        icmpSocket.Bind(new IPEndPoint(_localAddress, 0));

        // Create endpoint with scope ID if available
        IPEndPoint remoteEP;
        if (address is IPAddress ipv6Address && ipv6Address.IsIPv6LinkLocal)
        {
            // Get the interface index for the local address
            var interfaceIndex = NetworkInterface.GetAllNetworkInterfaces()
                .First(i => i.GetIPProperties().UnicastAddresses
                    .Any(a => a.Address.Equals(_localAddress)))
                .GetIPProperties().GetIPv6Properties().Index;

            // Create a new IPAddress with the same address bytes but the correct scope ID  
            var addressWithScope = ipv6Address.ScopeId == 0
                ? new IPAddress(ipv6Address.GetAddressBytes(), interfaceIndex)
                : ipv6Address;

            remoteEP = new IPEndPoint(addressWithScope, port);
        }
        else
        {
            remoteEP = new IPEndPoint(address, port);
        }

        try
        {
            // First attempt
            byte[] packet = new byte[0]; // Empty UDP packet
            await udpSocket.SendToAsync(new ArraySegment<byte>(packet), SocketFlags.None, remoteEP);

            byte[] buffer = new byte[1024];
            var receiveTask = icmpSocket.ReceiveAsync(new ArraySegment<byte>(buffer), SocketFlags.None);

            if (await Task.WhenAny(receiveTask, Task.Delay(timeout)) == receiveTask)
            {
                int received = await receiveTask;
                if (received > 0)
                {
                    // Check if it's an ICMPv6 Destination Unreachable message
                    if (buffer[0] == 1 && buffer[1] == 4) // Type 1 = Destination Unreachable, Code 4 = Port Unreachable
                    {
                        // Verify this ICMP response is for our UDP packet
                        byte[] originalDstPort = new byte[2];
                        originalDstPort[0] = (byte)(port >> 8);
                        originalDstPort[1] = (byte)(port & 0xFF);

                        if (buffer[48 + 2] == originalDstPort[0] && buffer[48 + 3] == originalDstPort[1])
                        {
                            return "closed";
                        }
                    }
                }
            }

            // Second attempt
            await udpSocket.SendToAsync(new ArraySegment<byte>(packet), SocketFlags.None, remoteEP);
            receiveTask = icmpSocket.ReceiveAsync(new ArraySegment<byte>(buffer), SocketFlags.None);

            if (await Task.WhenAny(receiveTask, Task.Delay(timeout)) == receiveTask)
            {
                int received = await receiveTask;
                if (received > 0)
                {
                    if (buffer[0] == 1 && buffer[1] == 4)
                    {
                        byte[] originalDstPort = new byte[2];
                        originalDstPort[0] = (byte)(port >> 8);
                        originalDstPort[1] = (byte)(port & 0xFF);

                        if (buffer[48 + 2] == originalDstPort[0] && buffer[48 + 3] == originalDstPort[1])
                        {
                            return "closed";
                        }
                    }
                }
            }
        }
        catch (SocketException ex)
        {
            // Socket error, consider port open
            Console.Error.WriteLine($"Socket error: {ex.Message}");
            return "open";
        }

        return "open";
    }

    private async Task<string> UdpScan(IPAddress address, int port, int timeout)
    {
        // Create UDP socket for sending
        using Socket udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        udpSocket.Bind(new IPEndPoint(_localAddress, 0));

        // Create ICMP socket for receiving port unreachable messages
        using Socket icmpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
        icmpSocket.Bind(new IPEndPoint(_localAddress, 0));

        try
        {
            // First attempt
            byte[] packet = new byte[0]; // Empty UDP packet
            EndPoint remoteEP = new IPEndPoint(address, port);
            await udpSocket.SendToAsync(new ArraySegment<byte>(packet), SocketFlags.None, remoteEP);

            byte[] buffer = new byte[1024];
            var receiveTask = icmpSocket.ReceiveAsync(new ArraySegment<byte>(buffer), SocketFlags.None);

            if (await Task.WhenAny(receiveTask, Task.Delay(timeout)) == receiveTask)
            {
                int received = await receiveTask;
                if (received > 0)
                {
                    // Check if it's an ICMP Destination Unreachable message
                    if (buffer[20] == 3 && buffer[21] == 3) // Type 3 = Destination Unreachable, Code 3 = Port Unreachable
                    {
                        // Verify this ICMP response is for our UDP packet
                        byte[] originalDstPort = new byte[2];
                        originalDstPort[0] = (byte)(port >> 8);
                        originalDstPort[1] = (byte)(port & 0xFF);

                        if (buffer[48 + 2] == originalDstPort[0] && buffer[48 + 3] == originalDstPort[1])
                        {
                            return "closed";
                        }
                    }
                }
            }

            // Second attempt
            await udpSocket.SendToAsync(new ArraySegment<byte>(packet), SocketFlags.None, remoteEP);
            receiveTask = icmpSocket.ReceiveAsync(new ArraySegment<byte>(buffer), SocketFlags.None);

            if (await Task.WhenAny(receiveTask, Task.Delay(timeout)) == receiveTask)
            {
                int received = await receiveTask;
                if (received > 0)
                {
                    if (buffer[20] == 3 && buffer[21] == 3)
                    {
                        byte[] originalDstPort = new byte[2];
                        originalDstPort[0] = (byte)(port >> 8);
                        originalDstPort[1] = (byte)(port & 0xFF);

                        if (buffer[48 + 2] == originalDstPort[0] && buffer[48 + 3] == originalDstPort[1])
                        {
                            return "closed";
                        }
                    }
                }
            }
        }
        catch (SocketException ex)
        {
            // Socket error, consider port open/filtered
            Console.Error.WriteLine($"Socket error: {ex.Message}");
            return "open";
        }

        return "open";
    }
}