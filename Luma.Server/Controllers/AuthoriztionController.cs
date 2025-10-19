using Microsoft.AspNetCore.Mvc;

namespace Luma.Controllers
{
    [Route("/")]
    public class AuthoriztionController : Controller
    {
        [Route("authorize")]
        public IActionResult StartAuthorizationFlow()
        {
            return Ok();
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
