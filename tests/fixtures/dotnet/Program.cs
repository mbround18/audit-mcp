// Deliberately flawed: exists so .NET scanners have something to report.
// Contains an unused local, a swallowed exception, and non-conventional
// formatting that `dotnet format --verify-no-changes` will flag.
namespace Example;

public static class Program
{
    private const string Password = "hunter2";

    public static void Main()
    {
            var unused = 42;
        try
        {
            Console.WriteLine( Password );
        }
        catch (Exception)
        {
        }
    }
}
