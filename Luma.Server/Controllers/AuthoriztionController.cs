using Luma.Core.DTOs.Authorization;
using Luma.Core.Interfaces.Authentication;
using Luma.Core.Interfaces.Services;
using Luma.Server.Utility;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;

namespace Luma.Controllers
{
    [Route("/")]
    public class AuthoriztionController : Controller
    {
        private readonly IAuthorizeService _authorizeService;
        private readonly IUserLoginSessionCookieAccessor _userLoginSessionCookieAccessor;
        private readonly IUserLoginSessionProvider _userLoginSessionProvider;

        public AuthoriztionController(
            IAuthorizeService authorizeService,
            IUserLoginSessionCookieAccessor userLoginSessionCookieAccessor,
            IUserLoginSessionProvider userLoginSessionProvider
            )
        {
            _authorizeService = authorizeService;
            _userLoginSessionCookieAccessor = userLoginSessionCookieAccessor;
            _userLoginSessionProvider = userLoginSessionProvider;
        }

        [HttpGet]
        [Route("authorize")]
        public async Task<IActionResult> StartAuthorizationFlowAsync(AuthorizeRequestDTO authorizeArgs)
        {
            var (redirectSafe, result) = await _authorizeService.CreateAuthorizationCodeStateAsync(authorizeArgs);
            if (result.ErrorCode != null || result.Data == null)
            {
                return result.ToErrorResponse(redirectSafe, authorizeArgs.redirect_uri, authorizeArgs.response_mode);
            }

            var token = _userLoginSessionCookieAccessor.GetLoginSessionToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                return Redirect($"/login?state={result.State}");
            }

            var loginSession = await _userLoginSessionProvider.GetBySessionTokenAsync(token);
            if (loginSession == null)
            {
                return Redirect($"/login?state={result.State}");
            }

            var refreshedActivity = await _userLoginSessionProvider.RefreshActivityAsync(loginSession.Id);
            if (!refreshedActivity)
            {
                return Redirect($"/login?state={result.State}");
            }

            var prompts = (authorizeArgs.prompt ?? "")
                .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (prompts.Contains("login"))
            {
                await _userLoginSessionProvider.RevokeAsync(loginSession.Id, "Prompt=login requested");
                _userLoginSessionCookieAccessor.ClearLoginSessionToken();

                return Redirect($"/login?state={result.State}");
            }
            else if (prompts.Contains("consent"))
            {
                return Redirect($"/consent?state={result.State}");
            }
            else if (prompts.Contains("select_account"))
            {
                return Redirect($"/select-account?state={result.State}");
            }

            var auth = await _authorizeService.GenerateAuthorizationCodeAsync(result.State!);
            if (auth.ErrorCode != null)
            {
                return auth.ToErrorResponse(redirectSafe, authorizeArgs.redirect_uri, authorizeArgs.response_mode);
            }

            if (authorizeArgs.response_mode == "form_post")
            {
                return new ContentResult
                {
                    ContentType = "text/html",
                    Content = $"<html><body onload=\"document.forms[0].submit()\">" +
                  $"<form method='post' action='{authorizeArgs.redirect_uri}'>" +
                  $"<input type='hidden' name='code' value='{auth.Data}' />" +
                  $"<input type='hidden' name='state' value='{auth.State}' />" +
                  "</form></body></html>"
                };
            }
            else
            {
                var queryParams = new Dictionary<string, string?>
                {
                    ["code"] = auth.Data,
                    ["state"] = auth.State
                };

                var fullUri = QueryHelpers.AddQueryString(result.Data, queryParams);

                return Redirect(fullUri);
            }
        }

        [Route("token")]
        public IActionResult TokenExchange()
        {
            return Ok();
        }

        [Route("mtls/token")]
        public IActionResult MTLS_TokenExchange()
        {
            return Ok();
        }

        [Route("introspect")]
        public IActionResult IntrospectToken()
        {
            return Ok();
        }

        [Route("mtls/introspect")]
        public IActionResult MTLS_IntrospectToken()
        {
            return Ok();
        }

        [Route("token/exchange")]
        public IActionResult TokenExchangeToken()
        {
            return Ok();
        }

        [Route("revoke")]
        public IActionResult RevokeToken()
        {
            return Ok();
        }

        [Route("userinfo")]
        public IActionResult UserInfo()
        {
            return Ok();
        }

        [Route(".well-known/openid-configuration")]
        public IActionResult OpenIDProviderMetadata()
        {
            return Ok();
        }

        [Route(".well-known/oauth-authorization-server")]
        public IActionResult OAuthAuthorizationServerMetadata()
        {
            return Ok();
        }

        [Route("device/code")]
        public IActionResult DeviceCode()
        {
            return Ok();
        }
    }
}
