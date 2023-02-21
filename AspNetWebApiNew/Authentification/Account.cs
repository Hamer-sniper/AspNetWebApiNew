using AspNetWebApiNew.Interfaces;
using Microsoft.AspNetCore.Identity;

namespace AspNetWebApiNew.Authentification
{
    public class Account : ILogin
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public Account(UserManager<User> userManager, SignInManager<User> signInManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
        }

        /// <summary>
        /// Проверить все роли пользователя.
        /// </summary>
        /// <param name="login">Логин</param>
        /// <returns>Список ролей</returns>
        public async Task<List<string>> RoleChecker(string login)
        {
            var user = await _userManager.FindByNameAsync(login);
            var allRoles = _roleManager.Roles.ToList();

            List<string> rolesToAdd = new List<string>();

            foreach (var concreteRole in allRoles)
            {
                if (await _userManager.IsInRoleAsync(user, concreteRole.Name))
                    rolesToAdd.Add(concreteRole.Name);
            }
            return rolesToAdd;
        }

        /// <summary>
        /// Проверка логина и пароля.
        /// </summary>
        /// <param name="login"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public async Task<bool> LoginResultIsSucceed(string login, string password)
        {
            var user = await _userManager.FindByNameAsync(login);
            if (user == null)
                return false;

            var loginResult = await _signInManager.PasswordSignInAsync(login,
                password,
                false,
                lockoutOnFailure: false);

            if (loginResult.Succeeded)
                return true;

            return false;
        }
    }
}
