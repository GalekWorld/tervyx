using System.Security.Cryptography;
using System.Text;

internal static class SecretStore
{
    private static readonly string Root = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Tervyx", "Agent");

    public static string LoadToken()
    {
        var path = Path.Combine(Root, "enrollment.token");
        if (!File.Exists(path))
            throw new InvalidOperationException("Enrollment token is not provisioned");
        var protectedBytes = File.ReadAllBytes(path);
        return Encoding.UTF8.GetString(ProtectedData.Unprotect(
            protectedBytes, null, DataProtectionScope.LocalMachine));
    }

    public static void ProvisionToken(string token)
    {
        Directory.CreateDirectory(Root);
        var protectedBytes = ProtectedData.Protect(
            Encoding.UTF8.GetBytes(token), null, DataProtectionScope.LocalMachine);
        File.WriteAllBytes(Path.Combine(Root, "enrollment.token"), protectedBytes);
    }
}
