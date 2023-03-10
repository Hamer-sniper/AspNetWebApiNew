using AspNetWebApiNew.Authentification;
using AspNetWebApiNew.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Rewrite;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AspNetWebApiNew.Controllers
{
    public class TokenController : Controller
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IAccount _account;

        public TokenController(UserManager<User> userManager, SignInManager<User> signInManager, RoleManager<IdentityRole> roleManager, IAccount account)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _account = account;
        }

        private const string SECRET_KEY = "TQvgjeABMPOwCycOqah5EQu5yyVjpmVG";
        public static readonly SymmetricSecurityKey SIGNING_KEY = new
                      SymmetricSecurityKey(Encoding.UTF8.GetBytes(SECRET_KEY));

        [HttpGet]
        [Route("api/Token/{username}/{password}")]
        public async Task<IActionResult> Login(string username, string password)
        {
            var loginResult = await _account.LoginResultIsSucceed(username, password);

            if (loginResult)
            {
                var roleResult = await _account.RoleChecker(username);
                return new ObjectResult(GenerateToken(username, roleResult));
            }
            else
                return BadRequest();
        }

        [HttpGet]
        [Authorize(Roles = "Admin")]
        [Route("api/Register/{username}/{password}")]
        public async Task<IActionResult> Register(string username, string password)
        {
            var user = new User { UserName = username };
            var createResult = await _userManager.CreateAsync(user, password);

            if (createResult.Succeeded)
            {
                return new ObjectResult(GenerateToken(username, new List<string>()));
            }
            else
                return BadRequest();
        }

        private string GenerateToken(string username, IEnumerable<string> roles)
        {
            List<Claim> claimsToToken = new List<Claim> { new Claim(ClaimTypes.Name, username) };

            foreach (var role in roles)
                claimsToToken.Add(new Claim(ClaimTypes.Role, role));

            var token = new JwtSecurityToken(
                claims: claimsToToken,
                notBefore: new DateTimeOffset(DateTime.Now).DateTime,
                expires: new DateTimeOffset(DateTime.Now.AddMinutes(60)).DateTime,
                signingCredentials: new SigningCredentials(SIGNING_KEY,
                                                    SecurityAlgorithms.HmacSha256)
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
