using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Options
{
    public class LumaOptions
    {
        public DatabaseOptions Database { get; set; } = new();
        public TokenOptions Tokens { get; set; } = new();
        public KeyOptions Keys { get; set; } = new();
        public OAuthOptions OAuth { get; set; } = new();
    }
}
