using AspNetWebApiNew.Authentification;
using Microsoft.AspNetCore.Identity;

namespace AspNetWebApiNew.Roles
{
    public class RoleInitializer
    {
        public static async Task InitializeAsync(UserManager<User> userManager, RoleManager<IdentityRole> roleManager)
        {
            string adminName = "Administrator";
            string password = "123456aA!";

            string simpleUserName = "user1";
            string simpleUserPassword = "123456aA!";

            if (await roleManager.FindByNameAsync("Admin") == null)
            {
                await roleManager.CreateAsync(new IdentityRole("Admin"));
            }
            if (await roleManager.FindByNameAsync("User") == null)
            {
                await roleManager.CreateAsync(new IdentityRole("User"));
            }
            if (await userManager.FindByNameAsync(adminName) == null)
            {
                User admin = new User {UserName = adminName };
                IdentityResult result = await userManager.CreateAsync(admin, password);
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(admin, "Admin");
                }
            }

            if (await userManager.FindByNameAsync(simpleUserName) == null)
            {
                User simpleUser = new User { UserName = simpleUserName };
                IdentityResult result = await userManager.CreateAsync(simpleUser, simpleUserPassword);
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(simpleUser, "User");
                }
            }
        }
    }
}
