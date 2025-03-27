using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
class ArgumentParser
{
    public string InterfaceName { get; private set; } = "";
    public List<int> TcpPorts { get; private set; } = new();
    public List<int> UdpPorts { get; private set; } = new();
    public int Timeout { get; private set; } = 5000;
    public string Target { get; private set; } = "";

    public ArgumentParser(string[] args)
    {
        ParseArguments(args);
    }

    private void ParseArguments(string[] args)
    {
        if (args.Length == 0)
        {
            ListInterfaces();
            Environment.Exit(0);
        }

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-h":
                case "--help":
                    PrintHelp();
                    Environment.Exit(0);
                    break;
                case "-i":
                case "--interface":
                    if (i + 1 >= args.Length)
                    {
                        ListInterfaces();
                        Environment.Exit(0);
                    }
                    InterfaceName = args[++i];
                    break;
                case "-t":
                case "--pt":
                    if (i + 1 >= args.Length)
                    {
                        throw new Exception("Error: No port range specified.");
                    }
                    TcpPorts = ParsePortRange(args[++i]);
                    break;
                case "-u":
                case "--pu":
                    if (i + 1 >= args.Length)
                    {
                        throw new Exception("Error: No port range specified.");
                    }
                    UdpPorts = ParsePortRange(args[++i]);
                    break;
                case "-w":
                case "--wait":
                    if (i + 1 >= args.Length)
                    {
                        throw new Exception("Error: No timeout specified.");
                    }
                    Timeout = int.Parse(args[++i]);
                    break;
                default:
                    Target = args[i];
                    break;
            }
        }

        // Mandatory arguments checks
        if (string.IsNullOrEmpty(InterfaceName))
        {
            throw new Exception("Error: No interface specified.");
        }
        if (string.IsNullOrEmpty(Target))
        {
            throw new Exception("Error: No target specified.");
        }
        if (TcpPorts.Count == 0 && UdpPorts.Count == 0)
        {
            throw new Exception("Error: No ports specified.");
        }
    }

    private List<int> ParsePortRange(string input)
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

    static void ListInterfaces()
    {
        Console.WriteLine("Available Network Interfaces:");
        foreach (var netInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            Console.WriteLine($"{netInterface.Name} - {netInterface.OperationalStatus}");
        }
    }

    private void PrintHelp()
    {
        Console.WriteLine("./ipk-l4-scan {-h} [-i interface | --interface interface] [--pu port-ranges | --pt port-ranges | -u port-ranges | -t port-ranges] {-w timeout} [hostname | ip-address]");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  -h, --help: Display help message");
        Console.WriteLine("  -i, --interface: Select network interface");
        Console.WriteLine("  -t, --pt: TCP ports to scan (1,2,3 or 1-1024)");
        Console.WriteLine("  -u, --pu: UDP ports to scan (1,2,3 or 1-1024)");
        Console.WriteLine("  -w, --wait: Timeout in milliseconds (default: 5000)");
    }
}
