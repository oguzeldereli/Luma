using Luma.Core.Options.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Options
{
    public class TokenOptions
    {
        public MagicLinkTokenOptions MagicLinkToken { get; set; } = new();
        public NumericCodeTokenOptions NumericCodeToken { get; set; } = new();
    }
}
