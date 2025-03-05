using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

class Program
{
    /// <summary>
    /// The main entry point for the application.
    /// </summary>
    /// <param name="args">Command-line arguments.</param>
    static async Task Main(string[] args)
    {
        if (args.Length == 0)
        {
            ListInterfaces();
            return;
        }

        string interfaceName = null;
        List<int> tcpPorts = new();
        int timeout = 5000;
        string target = null;

        // Parse command-line arguments
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-i": case "--interface":
                    interfaceName = args[++i];
                    break;
                case "-t": case "--pt":
                    tcpPorts = ParsePortRange(args[++i]);
                    break;
                case "-w": case "--wait":
                    timeout = int.Parse(args[++i]);
                    break;
                default:
                    target = args[i];
                    break;
            }
        }

        if (string.IsNullOrEmpty(target))
        {
            Console.WriteLine("Error: No target specified.");
            return;
        }

        IPAddress[] addresses = Dns.GetHostAddresses(target);
        foreach (var address in addresses)
        {
            Console.WriteLine($"Scanning {address}...");
            await ScanTcpPorts(address, tcpPorts, timeout);
        }
    }

    /// <summary>
    /// Lists all available network interfaces.
    /// </summary>
    static void ListInterfaces()
    {
        Console.WriteLine("Available Network Interfaces:");
        foreach (var netInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            Console.WriteLine($"{netInterface.Name} - {netInterface.OperationalStatus}");
        }
    }

    /// <summary>
    /// Parses a string representing a range of ports.
    /// </summary>
    /// <param name="input">The input string containing port ranges.</param>
    /// <returns>A list of integers representing the parsed ports.</returns>
    static List<int> ParsePortRange(string input)
    {
        return input.Split(',').SelectMany(part =>
        {
            if (part.Contains('-'))
            {
                var range = part.Split('-').Select(int.Parse).ToArray();
                return Enumerable.Range(range[0], range[1] - range[0] + 1);
            }
            else return new List<int> { int.Parse(part) };
        }).ToList();
    }

    /// <summary>
    /// Scans the specified TCP ports on the given IP address.
    /// </summary>
    /// <param name="address">The IP address to scan.</param>
    /// <param name="ports">The list of TCP ports to scan.</param>
    /// <param name="timeout">The timeout for each scan in milliseconds.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    static async Task ScanTcpPorts(IPAddress address, List<int> ports, int timeout)
    {
        foreach (var port in ports)
        {
            var result = await TcpSynScan(address, port, timeout);
            Console.WriteLine($"{port}/tcp {result}");
        }
    }

    /// <summary>
    /// Performs a TCP SYN scan on the specified port of the given IP address.
    /// </summary>
    /// <param name="address">The IP address to scan.</param>
    /// <param name="port">The TCP port to scan.</param>
    /// <param name="timeout">The timeout for the scan in milliseconds.</param>
    /// <returns>A task representing the asynchronous operation, with a result indicating the port status.</returns>
    static async Task<string> TcpSynScan(IPAddress address, int port, int timeout)
    {
        using Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Tcp);
        socket.Bind(new IPEndPoint(IPAddress.Any, 0));
        socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

        byte[] packet = BuildTcpSynPacket(address, port);
        EndPoint remoteEP = new IPEndPoint(address, port);
        await socket.SendToAsync(new ArraySegment<byte>(packet), SocketFlags.None, remoteEP);

        byte[] buffer = new byte[1024];
        socket.ReceiveTimeout = timeout;
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
            return "filtered";
        }
        return "closed";
    }

    /// <summary>
    /// Builds a TCP SYN packet for the specified IP address and port.
    /// </summary>
    /// <param name="address">The destination IP address.</param>
    /// <param name="port">The destination port.</param>
    /// <returns>A byte array representing the TCP SYN packet.</returns>
    static byte[] BuildTcpSynPacket(IPAddress address, int port)
    {
        byte[] packet = new byte[40]; // IP Header (20 bytes) + TCP Header (20 bytes)
        Random rand = new Random();
        
        // Fill IP Header
        packet[0] = 0x45; // Version and IHL
        packet[1] = 0x00; // Type of Service
        packet[2] = 0x00; packet[3] = 0x28; // Total Length (40 bytes)
        packet[4] = 0x00; packet[5] = 0x00; // Identification
        packet[6] = 0x40; packet[7] = 0x00; // Flags and Fragment Offset
        packet[8] = 0x40; // TTL (64)
        packet[9] = 0x06; // Protocol (TCP)
        packet[10] = 0x00; packet[11] = 0x00; // Checksum (Calculated later)

        byte[] srcAddr = new byte[] { 127, 0, 0, 1 }; // Localhost IP (update dynamically)
        Buffer.BlockCopy(srcAddr, 0, packet, 12, 4);
        byte[] destAddr = address.GetAddressBytes();
        Buffer.BlockCopy(destAddr, 0, packet, 16, 4);

        // Fill TCP Header
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
        packet[36] = 0x00; packet[37] = 0x00; // Checksum (Calculated later)
        packet[38] = 0x00; packet[39] = 0x00; // Urgent Pointer

        return packet;
    }

    /// <summary>
    /// Analyzes the response buffer to determine the port status.
    /// </summary>
    /// <param name="buffer">The response buffer.</param>
    /// <returns>A string indicating the port status ("open", "closed", or "filtered").</returns>
    static string AnalyzeResponse(byte[] buffer)
    {
        if (buffer[33] == 0x12) // SYN-ACK response
            return "open";
        if (buffer[33] == 0x14) // RST-ACK response
            return "closed";
        return "filtered";
    }
}