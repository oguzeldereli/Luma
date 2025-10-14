using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Options.Keys
{
    public class HmacKeyOptions
    {
        public string DefaultKeyId { get; set; } = string.Empty;
        public Dictionary<string, string> HmacKeys { get; set; } = new();
    }
}
