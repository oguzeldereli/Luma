using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Models.Auth
{
    public record JsonWebKeySetEntry(
        string kty,
        string kid,
        string use,
        string alg,
        string n,
        string e);
}
