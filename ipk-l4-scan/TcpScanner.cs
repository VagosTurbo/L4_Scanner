using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

class TcpScanner : Scanner
{
    private IPAddress _localAddress;

    public TcpScanner(IPAddress localAddress)
    {
        _localAddress = localAddress;
    }

    public async Task ScanPorts(IPAddress address, List<int> ports, int timeout)
    {
        bool isIpv6 = address.AddressFamily == AddressFamily.InterNetworkV6;
        foreach (var port in ports)
        {
            var result = isIpv6 ?
                await TcpSynScanIpv6(address, port, timeout) :
                await TcpSynScan(address, port, timeout);
            Console.WriteLine($"{address} {port} tcp {result}");
        }
    }

    private async Task<string> TcpSynScanIpv6(IPAddress address, int port, int timeout)
    {
        using Socket socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.Tcp);
        socket.Bind(new IPEndPoint(_localAddress, 0));

        byte[] packet = BuildTcpSynPacketIpv6(address, port);
        EndPoint remoteEP = new IPEndPoint(address, port);
        await socket.SendToAsync(new ArraySegment<byte>(packet), SocketFlags.None, remoteEP);

        byte[] buffer = new byte[1024];
        var receiveTask = socket.ReceiveAsync(new ArraySegment<byte>(buffer), SocketFlags.None);

        try
        {
            if (await Task.WhenAny(receiveTask, Task.Delay(timeout)) == receiveTask)
            {
                // Received response within timeout
                int received = await receiveTask;
                if (received > 0)
                {
                    return AnalyzeResponseIpv6(buffer);
                }

                // Try one more time
                await socket.SendToAsync(new ArraySegment<byte>(packet), SocketFlags.None, remoteEP);
                receiveTask = socket.ReceiveAsync(new ArraySegment<byte>(buffer), SocketFlags.None);

                if (await Task.WhenAny(receiveTask, Task.Delay(timeout)) == receiveTask)
                {
                    received = await receiveTask;
                    if (received > 0)
                    {
                        return AnalyzeResponseIpv6(buffer);
                    }
                }
            }
            else
            {
                // Timeout occurred
                return "filtered";
            }
        }
        catch (SocketException ex)
        {
            Console.Error.WriteLine($"Socket error: {ex.Message}");
            return "filtered";
        }

        return "filtered";
    }

    private string AnalyzeResponseIpv6(byte[] buffer)
    {
        // In IPv6, TCP header starts at offset 40 (after IPv6 header)
        byte flags = buffer[53];  // 40 (IPv6 header) + 13 (TCP flags offset)

        if (flags == 0x12) // SYN-ACK
            return "open";
        if (flags == 0x14) // RST
            return "closed";

        return "filtered";
    }

    private byte[] BuildTcpSynPacketIpv6(IPAddress address, int port)
    {
        byte[] packet = new byte[60]; // 40 bytes IPv6 header + 20 bytes TCP header
        Random rand = new Random();

        // IPv6 Header
        packet[0] = 0x60; // Version (6) << 4 | Traffic Class high nibble (0)
        packet[1] = 0x00; // Traffic Class low nibble (0) | Flow Label high 4 bits (0)
        packet[2] = 0x00; packet[3] = 0x00; // Flow Label low 16 bits
        packet[4] = 0x00; packet[5] = 0x14; // Payload Length (20 bytes TCP header)
        packet[6] = 0x06; // Next Header (TCP)
        packet[7] = 0x40; // Hop Limit (64)

        // Source IPv6 Address (16 bytes)
        byte[] srcAddr = _localAddress.GetAddressBytes();
        Buffer.BlockCopy(srcAddr, 0, packet, 8, 16);

        // Destination IPv6 Address (16 bytes)
        byte[] destAddr = address.GetAddressBytes();
        Buffer.BlockCopy(destAddr, 0, packet, 24, 16);

        // TCP Header (starts at offset 40)
        ushort srcPort = (ushort)rand.Next(1024, 65535);
        packet[40] = (byte)(srcPort >> 8);
        packet[41] = (byte)(srcPort & 0xFF);
        packet[42] = (byte)(port >> 8);
        packet[43] = (byte)(port & 0xFF);
        packet[44] = 0x00; packet[45] = 0x00; packet[46] = 0x00; packet[47] = 0x00; // Sequence Number
        packet[48] = 0x00; packet[49] = 0x00; packet[50] = 0x00; packet[51] = 0x00; // Acknowledgment Number
        packet[52] = 0x50; // Data Offset (5 * 4 = 20 bytes), Reserved
        packet[53] = 0x02; // Flags (SYN)
        packet[54] = 0x72; packet[55] = 0x10; // Window Size
        packet[56] = 0x00; packet[57] = 0x00; // Checksum (to be calculated)
        packet[58] = 0x00; packet[59] = 0x00; // Urgent Pointer

        // Calculate TCP checksum for IPv6
        ushort tcpChecksum = ComputeTcpChecksumIpv6(packet, srcAddr, destAddr);
        packet[56] = (byte)(tcpChecksum >> 8);
        packet[57] = (byte)(tcpChecksum & 0xFF);

        return packet;
    }

    private ushort ComputeTcpChecksumIpv6(byte[] packet, byte[] srcAddr, byte[] destAddr)
    {
        int tcpLength = 20;
        byte[] pseudoHeader = new byte[40 + tcpLength]; // IPv6 pseudo-header (40 bytes) + TCP segment

        // Pseudo Header for IPv6 (src IP, dest IP, TCP length, zeros, next header)
        Buffer.BlockCopy(srcAddr, 0, pseudoHeader, 0, 16);
        Buffer.BlockCopy(destAddr, 0, pseudoHeader, 16, 16);
        pseudoHeader[32] = 0x00; pseudoHeader[33] = 0x00; pseudoHeader[34] = 0x00; pseudoHeader[35] = (byte)tcpLength;
        pseudoHeader[36] = 0x00; pseudoHeader[37] = 0x00; pseudoHeader[38] = 0x00; pseudoHeader[39] = 0x06; // Next Header (TCP)

        // Copy TCP Header
        Buffer.BlockCopy(packet, 40, pseudoHeader, 40, tcpLength);

        return ComputeChecksum(pseudoHeader, 0, pseudoHeader.Length);
    }

    private async Task<string> TcpSynScan(IPAddress address, int port, int timeout)
    {
        using Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Tcp);
        socket.Bind(new IPEndPoint(_localAddress, 0));
        socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

        byte[] packet = BuildTcpSynPacket(address, port);
        EndPoint remoteEP = new IPEndPoint(address, port);
        await socket.SendToAsync(new ArraySegment<byte>(packet), SocketFlags.None, remoteEP);

        byte[] buffer = new byte[1024];
        var receiveTask = socket.ReceiveAsync(new ArraySegment<byte>(buffer), SocketFlags.None);

        try
        {
            if (await Task.WhenAny(receiveTask, Task.Delay(timeout)) == receiveTask)
            {
                // Received response within timeout
                int received = await receiveTask;
                if (received > 0)
                {
                    // If the first response is not filtered, return it
                    String result = AnalyzeResponse(buffer);
                    if (result != "filtered")
                    {
                        return result;
                    }
                }

                // Try one more time
                await socket.SendToAsync(new ArraySegment<byte>(packet), SocketFlags.None, remoteEP);
                receiveTask = socket.ReceiveAsync(new ArraySegment<byte>(buffer), SocketFlags.None);

                if (await Task.WhenAny(receiveTask, Task.Delay(timeout)) == receiveTask)
                {
                    received = await receiveTask;
                    if (received > 0)
                    {
                        return AnalyzeResponse(buffer);
                    }
                }
            }
            else
            {
                // Timeout occurred
                return "filtered";
            }
        }
        catch (SocketException)
        {
            return "filtered";
        }

        return "filtered";
    }

    private string AnalyzeResponse(byte[] buffer)
    {
        byte flags = buffer[33];

        if (flags == 0x12) // SYN-ACK
            return "open";
        if (flags == 0x14) // RST
            return "closed";

        return "filtered";
    }

    private byte[] BuildTcpSynPacket(IPAddress address, int port)
    {
        byte[] packet = new byte[40]; // 20 bytes for IP header + 20 bytes for TCP header
        Random rand = new Random();

        // IP Header
        packet[0] = 0x45; // Version (4) + IHL (5)
        packet[1] = 0x00; // Type of Service
        packet[2] = 0x00; packet[3] = 0x28; // Total Length = 40 bytes
        packet[4] = 0x00; packet[5] = 0x00; // Identification
        packet[6] = 0x40; packet[7] = 0x00; // Flags and Fragment Offset
        packet[8] = 0x40; // TTL (64)
        packet[9] = 0x06; // Protocol (TCP)
        packet[10] = 0x00; packet[11] = 0x00; // Checksum (to be calculated)

        byte[] srcAddr = _localAddress.GetAddressBytes();
        Buffer.BlockCopy(srcAddr, 0, packet, 12, 4);
        byte[] destAddr = address.GetAddressBytes();
        Buffer.BlockCopy(destAddr, 0, packet, 16, 4);

        // TCP Header
        ushort srcPort = (ushort)rand.Next(1024, 65535);
        packet[20] = (byte)(srcPort >> 8);
        packet[21] = (byte)(srcPort & 0xFF);
        packet[22] = (byte)(port >> 8);
        packet[23] = (byte)(port & 0xFF);
        packet[24] = 0x00; packet[25] = 0x00; packet[26] = 0x00; packet[27] = 0x00; // Sequence Number
        packet[28] = 0x00; packet[29] = 0x00; packet[30] = 0x00; packet[31] = 0x00; // Acknowledgment Number
        packet[32] = 0x50; // Data Offset (5 * 4 = 20 bytes), Reserved
        packet[33] = 0x02; // Flags (SYN)
        packet[34] = 0x72; packet[35] = 0x10; // Window Size
        packet[36] = 0x00; packet[37] = 0x00; // Checksum (to be calculated)
        packet[38] = 0x00; packet[39] = 0x00; // Urgent Pointer

        // Compute Checksums
        ushort ipChecksum = ComputeChecksum(packet, 0, 20);
        packet[10] = (byte)(ipChecksum >> 8);
        packet[11] = (byte)(ipChecksum & 0xFF);

        ushort tcpChecksum = ComputeTcpChecksum(packet, srcAddr, destAddr);
        packet[36] = (byte)(tcpChecksum >> 8);
        packet[37] = (byte)(tcpChecksum & 0xFF);

        return packet;
    }

    private ushort ComputeChecksum(byte[] buffer, int offset, int length)
    {
        uint sum = 0;
        for (int i = offset; i < offset + length; i += 2)
        {
            ushort word = (ushort)((buffer[i] << 8) + (i + 1 < buffer.Length ? buffer[i + 1] : 0));
            sum += word;
        }

        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return (ushort)~sum;
    }

    private ushort ComputeTcpChecksum(byte[] packet, byte[] srcAddr, byte[] destAddr)
    {
        int tcpLength = 20;
        byte[] pseudoHeader = new byte[12 + tcpLength];

        // Pseudo Header (src IP, dest IP, protocol, TCP length)
        Buffer.BlockCopy(srcAddr, 0, pseudoHeader, 0, 4);
        Buffer.BlockCopy(destAddr, 0, pseudoHeader, 4, 4);
        pseudoHeader[8] = 0; // Reserved
        pseudoHeader[9] = 6; // TCP Protocol
        pseudoHeader[10] = 0; pseudoHeader[11] = (byte)tcpLength;

        // Copy TCP Header
        Buffer.BlockCopy(packet, 20, pseudoHeader, 12, tcpLength);

        return ComputeChecksum(pseudoHeader, 0, pseudoHeader.Length);
    }
}