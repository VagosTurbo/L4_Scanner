using System;
using System.Collections.Generic;

class ArgumentParser
{
    public string InterfaceName { get; private set; }
    public List<int> TcpPorts { get; private set; } = new();
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
                case "-i": case "--interface":
                    InterfaceName = args[++i];
                    break;
                case "-t": case "--pt": case "-u": case "--pu":
                    TcpPorts = ParsePortRange(args[++i]);
                    break;
                case "-w": case "--wait":
                    Timeout = int.Parse(args[++i]);
                    break;
                default:
                    Target = args[i];
                    break;
            }
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
}