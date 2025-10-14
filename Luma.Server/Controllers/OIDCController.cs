using Microsoft.AspNetCore.Mvc;

namespace Luma.Controllers
{
    [Route("/")]
    public class OIDCController : Controller
    {
        [Route("jwks")]
        public IActionResult JSONWebKeySet()
        {
            return Ok();
        }

        [Route("check-session")]
        public IActionResult CheckSession()
        {
            return Ok();
        }

        [Route("end-session")]
        public IActionResult EndSession()
        {
            return Ok();
        }

        [Route("logout")]
        public IActionResult Logout()
        {
            return Ok();
        }

        [Route("device_authorization")]
        public IActionResult DeviceAuthorization()
        {
            return Ok();
        }

        [Route("par")]
        public IActionResult PushedAuthorizationRequest()
        {
            return Ok();
        }

        [Route("registration")]
        public IActionResult ClientRegistration()
        {
            return Ok();
        }

        [Route("backchannel_authentication")]
        public IActionResult BackchannelAuthentication()
        {
            return Ok();
        }
    }
}
