using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Options.Tokens
{
    public class RefreshTokenOptions
    {
        public int ValidForDays { get; set; } = 30;
    }
}
