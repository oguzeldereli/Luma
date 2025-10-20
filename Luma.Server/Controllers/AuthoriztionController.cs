using Luma.Core.DTOs.Authorization;
using Luma.Core.Interfaces.Services;
using Microsoft.AspNetCore.Mvc;

namespace Luma.Controllers
{
    [Route("/")]
    public class AuthoriztionController : Controller
    {

        private readonly IAuthorizeService _authorizeService;

        public AuthoriztionController(
            IAuthorizeService authorizeService
            )
        {
            _authorizeService = authorizeService;
        }

        [Route("authorize")]
        public  async Task<IActionResult> StartAuthorizationFlowAsync(AuthorizeRequestDTO authorizeArgs)
        {
            var result = await _authorizeService.StartAuthorizationAsync(authorizeArgs);
            return Ok(result);
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
