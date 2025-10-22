using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Interfaces.Authentication
{
    public interface IUserLoginSessionCookieAccessor
    {
        string? GetLoginSessionToken();
        void SetLoginSessionToken(string token, DateTimeOffset expiresAt);
        void ClearLoginSessionToken();
    }
}
