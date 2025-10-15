using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Options.Keys
{
    public class JwtKeyOptions
    {
        public string SigningAlgorithm { get; set; } = "RS256";
        public string DefaultKeyId { get; set; } = string.Empty;
        public Dictionary<string, JwtKeyEntry> Keys { get; set; } = new();
    }
}
