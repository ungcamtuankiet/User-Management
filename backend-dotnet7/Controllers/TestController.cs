using backend_dotnet7.Core.Constants;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace backend_dotnet7.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TestController : ControllerBase
    {
        [HttpGet]
        [Route("get-public")]
        public IActionResult GetPublicData()
        {
            return Ok("Public data");
        }

        [HttpGet]
        [Route("get-user-role")]
        [Authorize(Roles = StaticUserRole.USER)]
        public IActionResult GetUserData()
        {
            return Ok("User Role data");
        }

        [HttpGet]
        [Route("get-manager-role")]
        [Authorize(Roles = StaticUserRole.MANAGER)]
        public IActionResult GetManagerData()
        {
            return Ok("Manager Role data");
        }

        [HttpGet]
        [Route("get-admin-role")]
        [Authorize(Roles = StaticUserRole.ADMIN)]
        public IActionResult GetAdminData()
        {
            return Ok("Admin Role data");
        }

        [HttpGet]
        [Route("get-owner-role")]
        [Authorize(Roles = StaticUserRole.OWNER)]
        public IActionResult GetOwnerData()
        {
            return Ok("Owner Role data");
        }
    }
}
