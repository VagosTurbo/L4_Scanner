using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        if (args.Length == 0)
        {
            ListInterfaces();
            return;
        }

        var parser = new ArgumentParser(args);

        IPAddress srcAddress = GetInterfaceAddresses(parser.InterfaceName)[0];

        // Resolve target address
        IPAddress[] dstAddresses;
        if (IPAddress.TryParse(parser.Target, out var parsedAddress))
            dstAddresses = new IPAddress[] { parsedAddress };   // IP address provided
        else
            dstAddresses = Dns.GetHostAddresses(parser.Target); // Hostname provided
        
        // Check if target was found
        if (dstAddresses.Length == 0)
        {
            Console.Error.WriteLine("Error: Target not found.");
            Environment.Exit(1);
        }
        
        // Loop through all dstAddresses
        for (int i = 0; i < dstAddresses.Length; i++)
        {
            if (dstAddresses[i].AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {   // IPv6 address
                Console.WriteLine($"IPv6 address: {dstAddresses[i]}");
                continue;
            }  
            else if (dstAddresses[i].AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {   // IPv4 address
                Scanner scanner;
                if (parser.TcpPorts.Any())
                {
                    scanner = new TcpScanner(srcAddress);
                    await scanner.ScanPorts(dstAddresses[i], parser.TcpPorts, parser.Timeout);
                }
                if (parser.UdpPorts.Any())
                {
                    scanner = new UdpScanner(srcAddress);
                    await scanner.ScanPorts(dstAddresses[i], parser.UdpPorts, parser.Timeout);
                }
                continue;
            }
        }
    }

    static void ListInterfaces()
    {
        Console.WriteLine("Available Network Interfaces:");
        foreach (var netInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            Console.WriteLine($"{netInterface.Name} - {netInterface.OperationalStatus}");
        }
    }

    static IPAddress[] GetInterfaceAddresses(string interfaceName)
    {
        var netInterface = NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(ni => ni.Name.Equals(interfaceName, StringComparison.OrdinalIgnoreCase));

        if (netInterface == null)
        {
            return Array.Empty<IPAddress>();
        }

        return netInterface.GetIPProperties()
            .UnicastAddresses
            .Select(ua => ua.Address)
            .ToArray();
    }
}