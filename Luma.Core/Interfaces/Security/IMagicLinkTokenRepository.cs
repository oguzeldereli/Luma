using Luma.Models.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Interfaces.Auth
{
    public interface IMagicLinkTokenRepository : ITokenRepository<MagicLinkToken>
    {
        Task<(MagicLinkToken token, string plain)> CreateAsync(long userId);
    }
}
