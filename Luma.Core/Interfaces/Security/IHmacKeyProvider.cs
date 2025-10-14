using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Interfaces.Security
{
    public interface IHmacKeyProvider
    {
        string DefaultKeyId { get; }
        IEnumerable<string> AllKeyIds { get; }
        bool HasKey(string keyId);
        byte[] GetKey(string keyId);
    }
}
