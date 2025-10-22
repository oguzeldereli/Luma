using Luma.Core.Interfaces.Authentication;
using Luma.Core.Options;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Luma.Web.Providers
{
    public class UserLoginSessionCookieAccessor : IUserLoginSessionCookieAccessor
    {
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly IOptions<LumaOptions> _options;

        public UserLoginSessionCookieAccessor(
            IHttpContextAccessor contextAccessor, 
            IOptions<LumaOptions> options)
        {
            _contextAccessor = contextAccessor;
            _options = options;
        }

        public string? GetLoginSessionToken()
        {
            var ctx = _contextAccessor.HttpContext;
            if (ctx == null) return null;
            ctx.Request.Cookies.TryGetValue(_options.Value.AuthenticationServer.UserLoginSessionsCookieName, out var value);
            return value;
        }

        public void SetLoginSessionToken(string token, DateTimeOffset expiresAt)
        {
            var ctx = _contextAccessor.HttpContext;
            if (ctx == null) return;

            ctx.Response.Cookies.Append(_options.Value.AuthenticationServer.UserLoginSessionsCookieName, token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Expires = expiresAt
            });
        }

        public void ClearLoginSessionToken()
        {
            var ctx = _contextAccessor.HttpContext;
            ctx?.Response.Cookies.Delete(_options.Value.AuthenticationServer.UserLoginSessionsCookieName);
        }
    }
}
