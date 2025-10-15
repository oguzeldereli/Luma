using Luma.Core.Interfaces.Security;
using Luma.Core.Options;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace Luma.Infrastructure.Security
{
    public class JwtSigningKeyProvider : IJwtSigningKeyProvider
    {
        public string Algorithm { get; }
        public string DefaultKeyId { get; }

        private readonly Dictionary<string, (SecurityKey signing, SecurityKey verifying)> _keys = new();

        public JwtSigningKeyProvider(IOptions<LumaOptions> options)
        {
            var config = options.Value.Keys ?? throw new InvalidOperationException("Missing Keys configuration.");
            Algorithm = config.Jwt.SigningAlgorithm ?? "RS256";

            if (config.Jwt.Keys is not { Count: > 0 })
                throw new InvalidOperationException("No JWT keys configured under Luma:Keys:Jwt:Keys.");

            foreach (var (keyId, keyEntry) in config.Jwt.Keys)
            {
                if (string.IsNullOrWhiteSpace(keyEntry.PrivateKeyPath) ||
                    string.IsNullOrWhiteSpace(keyEntry.PublicKeyPath))
                    throw new InvalidOperationException($"JWT key '{keyId}' missing PrivateKeyPath or PublicKeyPath.");

                var privatePem = File.ReadAllText(keyEntry.PrivateKeyPath);
                var publicPem = File.ReadAllText(keyEntry.PublicKeyPath);

                switch (Algorithm.ToUpperInvariant())
                {
                    case "RS256":
                        {
                            var rsaPrivate = RSA.Create();
                            rsaPrivate.ImportFromPem(privatePem);
                            var rsaPublic = RSA.Create();
                            rsaPublic.ImportFromPem(publicPem);

                            var privKey = new RsaSecurityKey(rsaPrivate) { KeyId = keyId };
                            var pubKey = new RsaSecurityKey(rsaPublic) { KeyId = keyId };
                            _keys[keyId] = (privKey, pubKey);
                            break;
                        }

                    case "ES256":
                        {
                            var ecPrivate = ECDsa.Create();
                            ecPrivate.ImportFromPem(privatePem);
                            var ecPublic = ECDsa.Create();
                            ecPublic.ImportFromPem(publicPem);

                            var privKey = new ECDsaSecurityKey(ecPrivate) { KeyId = keyId };
                            var pubKey = new ECDsaSecurityKey(ecPublic) { KeyId = keyId };
                            _keys[keyId] = (privKey, pubKey);
                            break;
                        }

                    default:
                        throw new NotSupportedException($"Unsupported signing algorithm: {Algorithm}");
                }
            }

            DefaultKeyId =
                Environment.GetEnvironmentVariable("LUMA_JWT_DEFAULT_KEY_ID") ??
                config.Jwt.DefaultKeyId ??
                _keys.Keys.FirstOrDefault() ??
                throw new InvalidOperationException("No default key ID configured or available.");

            if (!_keys.ContainsKey(DefaultKeyId))
                throw new InvalidOperationException($"Default key ID '{DefaultKeyId}' not found among loaded keys.");
        }

        public IEnumerable<string> AllKeyIds => _keys.Keys;

        public bool HasKey(string keyId) => _keys.ContainsKey(keyId);

        public SecurityKey GetSigningKey(string keyId)
        {
            if (!_keys.TryGetValue(keyId, out var pair))
                throw new InvalidOperationException($"Unknown key ID '{keyId}'.");
            return pair.signing;
        }

        public SigningCredentials GetSigningCredentials(string? keyId = null)
        {
            keyId ??= DefaultKeyId;

            var signingKey = GetSigningKey(keyId);
            var algo = Algorithm.ToUpperInvariant() switch
            {
                "RS256" => SecurityAlgorithms.RsaSha256,
                "ES256" => SecurityAlgorithms.EcdsaSha256,
                "HS256" => SecurityAlgorithms.HmacSha256,
                _ => throw new NotSupportedException($"Unsupported algorithm: {Algorithm}")
            };

            return new SigningCredentials(signingKey, algo);
        }

        public SecurityKey GetVerificationKey(string keyId)
        {
            if (!_keys.TryGetValue(keyId, out var pair))
                throw new InvalidOperationException($"Unknown key ID '{keyId}'.");
            return pair.verifying;
        }
    }
}
