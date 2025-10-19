using Microsoft.AspNetCore.Mvc;

namespace Luma.Server.Controllers
{
    [Route("/")]
    public class AuthenticationController : Controller
    {
        [HttpGet]
        [Route("login")]
        public IActionResult LoginView()
        {
            return View("Login");
        }
    }
}
