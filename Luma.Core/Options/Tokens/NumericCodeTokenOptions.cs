using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Options.Tokens
{
    public class NumericCodeTokenOptions
    {
        public int ValidForMinutes { get; set; } = 15;
        public int DigitCount { get; set; } = 6;
    }
}
