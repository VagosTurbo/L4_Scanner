using System;
using System.Collections.Generic;

class ArgumentParser
{
    public string InterfaceName { get; private set; }
    public List<int> TcpPorts { get; private set; } = new();
    
    public List<int> UdpPorts { get; private set; } = new();
    public int Timeout { get; private set; } = 5000;
    public string Target { get; private set; }

    
    public ArgumentParser(string[] args)
    {
        ParseArguments(args);
    }

    private void ParseArguments(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-h": case "--help":
                    PrintHelp();
                    break;
                case "-i": case "--interface":
                    InterfaceName = args[++i];
                    break;
                case "-t": case "--pt": 
                    TcpPorts = ParsePortRange(args[++i]);
                    break;
                case "-u": case "--pu":
                    UdpPorts = ParsePortRange(args[++i]);
                    break;
                case "-w": case "--wait":
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
            Console.Error.WriteLine("Error: No interface specified.");
            Environment.Exit(1);
        }
        if (string.IsNullOrEmpty(Target))
        {
            Console.Error.WriteLine("Error: No target specified.");
            Environment.Exit(1);
        }
        if (TcpPorts.Count == 0 && UdpPorts.Count == 0)
        {
            Console.Error.WriteLine("Error: No ports specified.");
            Environment.Exit(1);
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

    private void PrintHelp()
    {
        Console.WriteLine("Usage: ipk-l4-scan [OPTIONS] TARGET");
        Console.WriteLine("Scan TCP/UDP ports of a target using raw sockets.");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  -i, --interface=IFACE  Network interface to use for scanning");
        Console.WriteLine("  -t, --pt=PORTS         Comma-separated list of TCP ports to scan");
        Console.WriteLine("  -w, --wait=TIMEOUT     Timeout for each port scan in milliseconds");
        Console.WriteLine("  -h, --help             Display this help message");
        Environment.Exit(0);
    }
}
