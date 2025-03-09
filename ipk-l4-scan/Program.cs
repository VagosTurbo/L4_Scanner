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

        if (string.IsNullOrEmpty(parser.Target) && string.IsNullOrEmpty(parser.InterfaceName))
        {
            Console.WriteLine("Error: No target or interface specified.");
            return;
        }

        IPAddress[] addresses;
        IPAddress localAddress = null;
        if (!string.IsNullOrEmpty(parser.InterfaceName))
        {
            addresses = GetInterfaceAddresses(parser.InterfaceName);
            if (addresses.Length == 0)
            {
                Console.WriteLine($"Error: No addresses found for interface {parser.InterfaceName}.");
                return;
            }
            localAddress = addresses[0]; // Use the first address of the interface
        }
        else
        {
            addresses = Dns.GetHostAddresses(parser.Target);
    
        }

        Console.WriteLine($"Interface: {parser.InterfaceName} ({addresses[0]})");
        var scanner = new TcpScanner(localAddress);
        foreach (var address in addresses)
        {
            Console.WriteLine($"Scanning {address}...");
            await scanner.ScanTcpPorts(address, parser.TcpPorts, parser.Timeout);
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