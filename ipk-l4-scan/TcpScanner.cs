using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

class TcpScanner
{
    private IPAddress _localAddress;

    public TcpScanner(IPAddress localAddress)
    {
        _localAddress = localAddress;
    }

    public async Task ScanTcpPorts(IPAddress address, List<int> ports, int timeout)
    {
        foreach (var port in ports)
        {
            var result = await TcpSynScan(address, port, timeout);
            Console.WriteLine($"{port}/tcp {result}");
        }
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
        socket.ReceiveTimeout = timeout;

        for (int attempt = 0; attempt < 2; attempt++) // Try twice before marking as filtered
        {
            try
            {
                int received = await socket.ReceiveAsync(new ArraySegment<byte>(buffer), SocketFlags.None);
                if (received > 0)
                {
                    return AnalyzeResponse(buffer);
                }
            }
            catch (SocketException)
            {
                if (attempt == 0) continue; // Try again
                return "filtered";
            }
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