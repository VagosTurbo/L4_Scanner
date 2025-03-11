using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

class UdpScanner : Scanner
{
    private IPAddress _localAddress;

    public UdpScanner(IPAddress localAddress)
    {
        _localAddress = localAddress;
    }

    public async Task ScanPorts(IPAddress address, List<int> ports, int timeout)
    {
        foreach (var port in ports)
        {
            var result = await UdpScan(address, port, timeout);
            Console.WriteLine($"{port}/udp {result}");
        }
    }

    private async Task<string> UdpScan(IPAddress address, int port, int timeout)
    {
        using Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(_localAddress, 0));

        byte[] packet = new byte[1]; // Minimal packet for UDP scan
        EndPoint remoteEP = new IPEndPoint(address, port);
        await socket.SendToAsync(new ArraySegment<byte>(packet), SocketFlags.None, remoteEP);

        byte[] buffer = new byte[1024];
        socket.ReceiveTimeout = timeout;

        try
        {
            var result = await socket.ReceiveFromAsync(new ArraySegment<byte>(buffer), SocketFlags.None, remoteEP);
            if (result.ReceivedBytes > 0)
            {
                if (buffer[20] == 3 && buffer[21] == 3) // ICMP type 3, code 3
                {
                    return "closed";
                }
            }
        }
        catch (SocketException)
        {
            return "open";
        }

        return "open";
    }
}