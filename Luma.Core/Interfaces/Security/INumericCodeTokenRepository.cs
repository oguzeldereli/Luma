using Luma.Core.Interfaces.Shared;
using Luma.Models.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Interfaces.Auth
{
    public interface INumericCodeTokenRepository : ITokenRepository<NumericCodeToken>
    {
        Task<(NumericCodeToken token, string plain)> CreateAsync(long userId);
    }
}
