namespace AspNetWebApiNew.Interfaces
{
    public interface IAccount
    {
        Task<bool> LoginResultIsSucceed(string login, string password);
        Task<List<string>> RoleChecker(string username);
    }
}
