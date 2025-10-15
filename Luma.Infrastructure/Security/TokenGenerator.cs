using System.Security.Cryptography;

namespace Luma.Infrastructure.Security
{
    public class TokenGenerator
    {
        private readonly TokenHasher _tokenHasher;

        public TokenGenerator(TokenHasher tokenHasher)
        {
            _tokenHasher = tokenHasher;
        }

        public (string plain, string hashed, string keyId) GenerateOpaqueToken(int numBytes = 32, string? keyId = null)
        {
            if (numBytes < 16)
                throw new ArgumentOutOfRangeException(nameof(numBytes));

            Span<byte> bytes = stackalloc byte[numBytes];
            RandomNumberGenerator.Fill(bytes);

            string plain = Convert.ToBase64String(bytes)
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');

            var (hashed, key) = _tokenHasher.ComputeHmacSha256(plain, keyId);
            return (plain, hashed, key);
        }

        public (string plain, string hashed, string keyId) GenerateNumericCode(int digits = 6, string? keyId = null)
        {
            if (digits < 1 || digits > 18)
                throw new ArgumentOutOfRangeException(nameof(digits),
                    "Digits must be between 1 and 18 to avoid overflow.");

            ulong max = (ulong)Math.Pow(10, digits);
            ulong result;

            do
            {
                Span<byte> buffer = stackalloc byte[8];
                RandomNumberGenerator.Fill(buffer);
                result = BitConverter.ToUInt64(buffer) % max;
            } while (result >= max);

            string plain = result.ToString($"D{digits}");
            var (hashed, key) = _tokenHasher.ComputeHmacSha256(plain, keyId);
            return (plain, hashed, key);
        }

        public (string plain, string hashed, string keyId) GenerateJwtTokenHash(string jwt, string? keyId = null)
        {
            var (hashed, key) = _tokenHasher.ComputeHmacSha256(jwt, keyId);
            return (jwt, hashed, key);
        }
    }
}
