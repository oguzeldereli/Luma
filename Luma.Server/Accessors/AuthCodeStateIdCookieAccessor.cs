using Luma.Core.Interfaces.Authentication;
using Luma.Core.Interfaces.Authorization;
using Luma.Core.Options;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Luma.Web.Providers
{
    public class AuthCodeStateIdCookieAccessor : IAuthorizationCodeStateIdCookieAccessor
    {
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly IOptions<LumaOptions> _options;

        public AuthCodeStateIdCookieAccessor(
            IHttpContextAccessor contextAccessor, 
            IOptions<LumaOptions> options)
        {
            _contextAccessor = contextAccessor;
            _options = options;
        }

        public string? GetAuthCodeStateIdToken()
        {
            var ctx = _contextAccessor.HttpContext;
            if (ctx == null) return null;
            ctx.Request.Cookies.TryGetValue(_options.Value.AuthenticationServer.AuthCodeStateIdCookieName, out var value);
            return value;
        }

        public void SetAuthCodeStateIdToken(string token)
        {
            var ctx = _contextAccessor.HttpContext;
            if (ctx == null) return;

            ctx.Response.Cookies.Append(_options.Value.AuthenticationServer.AuthCodeStateIdCookieName, token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Expires = DateTime.UtcNow + TimeSpan.FromMinutes(_options.Value.AuthenticationServer.AuthCodeStateIdCookieValidForMinutes)
            });
        }

        public void ClearAuthCodeStateIdToken()
        {
            var ctx = _contextAccessor.HttpContext;
            ctx?.Response.Cookies.Delete(_options.Value.AuthenticationServer.AuthCodeStateIdCookieName);
        }
    }
}
