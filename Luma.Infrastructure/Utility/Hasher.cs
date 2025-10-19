using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Infrastructure.Utility
{
    internal class Hasher
    {
        public static string StringSHA256_Base64(string input)
        {
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(input);
                var hashBytes = sha256.ComputeHash(bytes);
                return Convert.ToBase64String(hashBytes);
            }
        }
    }
}
