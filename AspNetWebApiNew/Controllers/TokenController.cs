using AspNetWebApiNew.Authentification;
using AspNetWebApiNew.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AspNetWebApiNew.Controllers
{
    public class TokenController : Controller
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly ILogin _login;

        public TokenController(UserManager<User> userManager, SignInManager<User> signInManager, ILogin login)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _login = login;
        }

        private const string SECRET_KEY = "TQvgjeABMPOwCycOqah5EQu5yyVjpmVG";
        public static readonly SymmetricSecurityKey SIGNING_KEY = new
                      SymmetricSecurityKey(Encoding.UTF8.GetBytes(SECRET_KEY));

        [HttpGet]
        [Route("api/Token/{username}/{password}")]
        public async Task<IActionResult> Get(string username, string password)
        {
            var loginResult = await _login.LoginResultIsSucceed(username, password);            

            if (loginResult)
            {
                var roleResult = await _login.RoleChecker(username);
                return new ObjectResult(GenerateToken(username, roleResult));
            }
            else
                return BadRequest();
        }

        // Generate a Token with expiration date and Claim meta-data.
        // And sign the token with the SIGNING_KEY
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
