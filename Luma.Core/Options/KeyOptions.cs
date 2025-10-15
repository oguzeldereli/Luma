using Luma.Core.Options.Keys;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Options
{
    public class KeyOptions
    {
        public HmacKeyOptions Hmac { get; set; } = new();
        public JwtKeyOptions Jwt { get; set; } = new();
    }
}
