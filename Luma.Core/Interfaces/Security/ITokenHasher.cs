using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Interfaces.Security
{
    public interface ITokenHasher
    {
        public (string hash, string keyId) ComputeHmacSha256(string input, string? keyId = null);
        public bool VerifyWithKey(string plain, string storedHash, string keyId);
        public bool Verify(string plain, string storedHash);
        public string ComputeHashForLookup(string plain, string keyId);
        public (string hashed, string keyId) ComputeJwtTokenHash(string jwt, string? keyId = null);
    }
}
