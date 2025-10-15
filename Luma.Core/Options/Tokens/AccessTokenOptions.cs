using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Options.Tokens
{
    public class AccessTokenOptions
    {
        public string Issuer { get; set; } = "Luma";
        public string TokenType { get; set; } = "Jwt";
        public int ValidForMinutes { get; set; } = 15;
        public string DefaultScope { get; set; } = "openid profile email";
    }
}
