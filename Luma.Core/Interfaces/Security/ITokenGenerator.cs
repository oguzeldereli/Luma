using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Interfaces.Security
{
    public interface ITokenGenerator
    {
        public (string plain, string hashed, string keyId) GenerateOpaqueToken(int numBytes = 32, string? keyId = null);
        public (string plain, string hashed, string keyId) GenerateNumericCode(int digits = 6, string? keyId = null);
    }
}
