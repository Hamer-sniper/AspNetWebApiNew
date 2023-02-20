using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using AspNetWebApiNew.Authentification;
using AspNetWebApiNew.Models;

namespace AspNetWebApiNew.DataContext
{
    public class DataBookContext : IdentityDbContext<User>
    {
        public DataBookContext(DbContextOptions options) : base(options) { }
    }
}
