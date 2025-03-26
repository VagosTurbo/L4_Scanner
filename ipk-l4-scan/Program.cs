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
        try
        {
            if (args.Length == 0)
            {
                ListInterfaces();
                return;
            }

            var parser = new ArgumentParser(args);

            // Get all addresses for the interface
            var interfaceAddresses = GetInterfaceAddresses(parser.InterfaceName);
            if (interfaceAddresses.Length == 0)
            {
                Console.Error.WriteLine($"Error: No addresses found for interface {parser.InterfaceName}");
                Environment.Exit(1);
            }

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
            foreach (var dstAddress in dstAddresses)
            {
                // Find matching source address family (IPv4 or IPv6)
                var srcAddress = interfaceAddresses.FirstOrDefault(addr => addr.AddressFamily == dstAddress.AddressFamily);
                if (srcAddress == null)
                {
                    continue; // Skip if no matching source address family found
                }

                Scanner scanner;
                if (parser.TcpPorts.Any())
                {
                    scanner = new TcpScanner(srcAddress);
                    await scanner.ScanPorts(dstAddress, parser.TcpPorts, parser.Timeout);
                }
                if (parser.UdpPorts.Any())
                {
                    scanner = new UdpScanner(srcAddress);
                    await scanner.ScanPorts(dstAddress, parser.UdpPorts, parser.Timeout);
                }
            }
        }
        catch (Exception ex)
        {
            if (ex.Message == "Help requested")
            {
                Console.WriteLine("./ipk-l4-scan {-h} [-i interface | --interface interface] [--pu port-ranges | --pt port-ranges | -u port-ranges | -t port-ranges] {-w timeout} [hostname | ip-address]");
                Console.WriteLine();
                Environment.Exit(0);
            }
            else
            {
                Console.Error.WriteLine(ex.Message);
                Environment.Exit(1);
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
        // Get all network interfaces and find the one with the matching name
        var netInterface = NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(ni => ni.Name.Equals(interfaceName, StringComparison.OrdinalIgnoreCase));

        // If no matching interface found, return empty array
        if (netInterface == null)
        {
            return Array.Empty<IPAddress>();
        }

        // Get all IP addresses for the matching interface
        return netInterface.GetIPProperties()
            .UnicastAddresses
            .Select(ua => ua.Address)
            .ToArray();
    }
}