public class MockUrlScanner : IUrlScanner
{
    public async Task<string> CheckUrlAsync(string url)
    {
        // This is a placeholder for a real implementation
        return "URL is malicious";
    }
}