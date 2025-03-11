// Scanner.cs
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;

public interface Scanner
{
    Task ScanPorts(IPAddress address, List<int> ports, int timeout);
}