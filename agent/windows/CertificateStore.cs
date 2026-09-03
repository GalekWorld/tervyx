using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

internal static class CertificateStore
{
    public static X509Certificate2 LoadClientCertificate(string thumbprint)
    {
        var normalized = thumbprint.Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant();
        if (normalized.Length != 40 || normalized.Any(c => !Uri.IsHexDigit(c)))
            throw new InvalidOperationException("A SHA-1 certificate thumbprint is required");
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var certificate = store.Certificates.Find(X509FindType.FindByThumbprint, normalized, validOnly: true)
            .OfType<X509Certificate2>().SingleOrDefault();
        if (certificate is null || certificate.NotAfter <= DateTime.UtcNow)
            throw new InvalidOperationException("No valid client certificate found in LocalMachine\\My");
        var clientAuthentication = "1.3.6.1.5.5.7.3.2";
        if (!certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>()
            .Any(extension => extension.EnhancedKeyUsages.Cast<Oid>()
                .Any(usage => usage.Value == clientAuthentication)))
            throw new InvalidOperationException("Certificate is not authorized for TLS client authentication");
        return certificate;
    }
}
