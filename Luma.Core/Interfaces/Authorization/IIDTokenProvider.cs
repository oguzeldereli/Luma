using Luma.Core.Models.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Interfaces.Authorization
{
    public interface IIDTokenProvider
    {
        Task<string> CreateAsync(long accessTokenId, string? nonce = null);
    }
}
