using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Interfaces.Authorization
{
    public interface IAuthorizationCodeStateIdCookieAccessor
    {
        string? GetAuthCodeStateIdToken();
        void SetAuthCodeStateIdToken(string token);
        void ClearAuthCodeStateIdToken();
    }
}
