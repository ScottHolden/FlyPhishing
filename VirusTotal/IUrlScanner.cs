public interface IUrlScanner
{
    Task<string> CheckUrlAsync(string url);
}