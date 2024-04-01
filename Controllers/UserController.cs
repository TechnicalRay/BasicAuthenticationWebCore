using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace BasicAuthenticationWebCore.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        [HttpGet]
        [Route("isAuthenticate")]
        public IActionResult isAuthenticateAPI()
        {
            return Ok("Authentication Successful.!");
        }
    }
}
