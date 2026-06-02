using Luma.Core.Options;
using System.Security.Cryptography;

namespace Luma.Server.Utility
{
    /// <summary>
    /// Generates development signing keys on first run so the server is runnable without manual key
    /// provisioning. If a configured JWT key's PEM files are missing, a fresh keypair (RSA for RS256,
    /// EC P-256 for ES256) is created and written to the configured paths. Existing files are left
    /// untouched. Intended for local/dev use — provision and manage keys explicitly in production.
    /// </summary>
    public static class LumaKeyBootstrap
    {
        public static void EnsureJwtKeys(LumaOptions options)
        {
            var jwt = options.Keys.Jwt;
            if (jwt.Keys is not { Count: > 0 })
                return;

            var algorithm = (jwt.SigningAlgorithm ?? "RS256").ToUpperInvariant();

            foreach (var (keyId, entry) in jwt.Keys)
            {
                if (string.IsNullOrWhiteSpace(entry.PrivateKeyPath) || string.IsNullOrWhiteSpace(entry.PublicKeyPath))
                    continue;

                if (File.Exists(entry.PrivateKeyPath) && File.Exists(entry.PublicKeyPath))
                    continue;

                var privateDir = Path.GetDirectoryName(Path.GetFullPath(entry.PrivateKeyPath));
                if (!string.IsNullOrEmpty(privateDir))
                    Directory.CreateDirectory(privateDir);

                string privatePem;
                string publicPem;

                switch (algorithm)
                {
                    case "ES256":
                        using (var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256))
                        {
                            privatePem = ec.ExportPkcs8PrivateKeyPem();
                            publicPem = ec.ExportSubjectPublicKeyInfoPem();
                        }
                        break;

                    default: // RS256
                        using (var rsa = RSA.Create(2048))
                        {
                            privatePem = rsa.ExportPkcs8PrivateKeyPem();
                            publicPem = rsa.ExportSubjectPublicKeyInfoPem();
                        }
                        break;
                }

                File.WriteAllText(entry.PrivateKeyPath, privatePem);
                File.WriteAllText(entry.PublicKeyPath, publicPem);
                Console.WriteLine($"[Luma] Generated development {algorithm} signing key '{keyId}' at {entry.PrivateKeyPath}.");
            }
        }
    }
}
