namespace AspNetWebApiNew.Interfaces
{
    public interface ILogin
    {
        Task<bool> LoginResultIsSucceed(string login, string password);
        Task<List<string>> RoleChecker(string username);
    }
}
