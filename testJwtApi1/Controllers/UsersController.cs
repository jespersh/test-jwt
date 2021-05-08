using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using testJwtApi1.Services;
using testJwtApi1.Models;

namespace testJwtApi1.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class UsersController : ControllerBase
    {
        private IUserService _userService;

        public UsersController(IUserService userService)
        {
            _userService = userService;
        }

        [AllowAnonymous]
        [HttpPost("authenticate")]
        public IActionResult Authenticate([FromBody] AuthenticateRequest model)
        {
            var response = _userService.Authenticate(model);

            if (response == null)
                return BadRequest(new { message = "Username or password is incorrect" });

            return Ok(response);
        }

        [HttpGet]
        public IActionResult GetAll()
        {
            var users = _userService.GetAll();
            return Ok(users);
        }

        [Authorize(Roles = "adserverservice")]
        [HttpGet("GetServices")]
        public IActionResult GetServices()
        {
            var users = _userService.GetAll();
            return Ok(users);
        }
    }
}
