using Luma.Core.Interfaces.Security;
using Luma.Core.Options;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Luma.Infrastructure.Providers
{
    public class HmacKeyProvider : IHmacKeyProvider
    {
        private readonly Dictionary<string, byte[]> _keys = new();
        public string DefaultKeyId { get; }

        public HmacKeyProvider(IOptions<LumaOptions> options)
        {
            var config = options.Value.Keys;

            foreach (var envKey in Environment.GetEnvironmentVariables().Keys.Cast<string>())
            {
                if (envKey.StartsWith("LUMA_HMACSHA256_KEY_", StringComparison.OrdinalIgnoreCase))
                {
                    var id = envKey["LUMA_HMACSHA256_KEY_".Length..];
                    var value = Environment.GetEnvironmentVariable(envKey)!;
                    try
                    {
                        _keys[id] = Convert.FromBase64String(value);
                    }
                    catch (FormatException)
                    {
                        throw new InvalidOperationException($"Invalid base64 encoding for environment key '{envKey}'.");
                    }
                }
            }

            if (config?.Hmac?.Keys != null)
            {
                foreach (var (id, base64) in config?.Hmac?.Keys!)
                {
                    if (!_keys.ContainsKey(id))
                    {
                        try
                        {
                            _keys[id] = Convert.FromBase64String(base64);
                        }
                        catch (FormatException)
                        {
                            throw new InvalidOperationException($"Invalid base64 encoding for key '{id}' in configuration.");
                        }
                    }
                }
            }

            DefaultKeyId =
                Environment.GetEnvironmentVariable("LUMA_HMACSHA256_DEFAULT_KEY_ID") ??
                config?.Hmac.DefaultKeyId ??
                throw new InvalidOperationException("Default key ID not configured in either environment or configuration.");

            if (!_keys.ContainsKey(DefaultKeyId))
                throw new InvalidOperationException($"Default key ID '{DefaultKeyId}' not found among loaded keys.");
        }

        public IEnumerable<string> AllKeyIds => _keys.Keys;

        public bool HasKey(string keyId) => _keys.ContainsKey(keyId);

        public byte[] GetKey(string keyId)
        {
            if (!_keys.TryGetValue(keyId, out var key))
                throw new InvalidOperationException($"Unknown key ID '{keyId}'.");
            return key;
        }
    }
}
