using Luma.Core.Interfaces.Security;
using System.Security.Cryptography;
using System.Text;

namespace Luma.Infrastructure.Security
{
    public class TokenHasher
    {
        private readonly IHmacKeyProvider _keyProvider;

        public TokenHasher(IHmacKeyProvider keyProvider)
        {
            _keyProvider = keyProvider;
        }

        public (string hash, string keyId) ComputeHmacSha256(string input, string? keyId = null)
        {
            keyId ??= _keyProvider.DefaultKeyId;

            if (!_keyProvider.HasKey(keyId))
                throw new InvalidOperationException($"Unknown HMAC key ID '{keyId}'.");

            var key = _keyProvider.GetKey(keyId);
            using var hmac = new HMACSHA256(key);

            var bytes = Encoding.UTF8.GetBytes(input);
            var hash = Convert.ToHexString(hmac.ComputeHash(bytes));

            return (hash, keyId);
        }

        public bool VerifyWithKey(string plain, string storedHash, string keyId)
        {
            if (!_keyProvider.HasKey(keyId))
                return false;

            var key = _keyProvider.GetKey(keyId);
            using var hmac = new HMACSHA256(key);

            var computed = hmac.ComputeHash(Encoding.UTF8.GetBytes(plain));
            var storedBytes = Convert.FromHexString(storedHash);

            return CryptographicOperations.FixedTimeEquals(computed, storedBytes);
        }

        public bool Verify(string plain, string storedHash)
        {
            if (VerifyWithKey(plain, storedHash, _keyProvider.DefaultKeyId))
                return true;

            foreach (var keyId in _keyProvider.AllKeyIds)
            {
                if (keyId == _keyProvider.DefaultKeyId)
                    continue;

                if (VerifyWithKey(plain, storedHash, keyId))
                    return true;
            }

            return false;
        }

        public string ComputeHashForLookup(string plain, string keyId) =>
            ComputeHmacSha256(plain, keyId).hash;
    }
}
