using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Options.Keys
{
    public class JwtKeyEntry
    {
        public string PrivateKeyPath { get; init; } = default!;
        public string PublicKeyPath { get; init; } = default!;
    }
}
