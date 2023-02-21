using AspNetWebApiNew.Authentification;
using AspNetWebApiNew.Controllers;
using AspNetWebApiNew.DataContext;
using AspNetWebApiNew.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

public class Program
{
    private static async Task Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddControllers();

        builder.Services.AddMvc(mvcOtions => mvcOtions.EnableEndpointRouting = false);

        builder.Services.AddDbContext<DataBookContext>(opt =>
          opt.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

        builder.Services.AddTransient<IDataBookData, DataBookData>();
        builder.Services.AddTransient<ILogin, Account>();

        builder.Services.AddIdentity<User, IdentityRole>()
            .AddEntityFrameworkStores<DataBookContext>()
            .AddDefaultTokenProviders();

        builder.Services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = "JwtBearer";
            options.DefaultChallengeScheme = "JwtBearer";
        })
               .AddJwtBearer("JwtBearer", jwtOptions =>
               {
                   jwtOptions.TokenValidationParameters = new TokenValidationParameters()
                   {
                       IssuerSigningKey = TokenController.SIGNING_KEY,
                       ValidateIssuer = false,
                       ValidateAudience = false,
                       ValidateIssuerSigningKey = true,
                       ValidateLifetime = true,
                       ClockSkew = TimeSpan.FromMinutes(5)
                   };
               });

        var app = builder.Build();

        using (var scope = app.Services.CreateScope())
        {
            var services = scope.ServiceProvider;
            try
            {
                var userManager = services.GetRequiredService<UserManager<User>>();
                var rolesManager = services.GetRequiredService<RoleManager<IdentityRole>>();
                await AspNetWebApiNew.Roles.RoleInitializer.InitializeAsync(userManager, rolesManager);
            }
            catch (Exception ex)
            {
                var logger = services.GetRequiredService<ILogger<Program>>();
                logger.LogError(ex, "An error occurred while seeding the database.");
            }
        }

        app.UseAuthentication();

        app.UseMvc();

        app.MapGet("/", () => "Api запущен!");

        app.Run();
    }
}