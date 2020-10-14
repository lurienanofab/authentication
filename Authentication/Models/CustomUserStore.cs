using Microsoft.AspNet.Identity;
using System;
using System.Threading.Tasks;

namespace Authentication.Models
{
    public class CustomUserStore : IUserStore<IdentityUser, int>
    {
        public Task CreateAsync(IdentityUser user)
        {
           
            throw new NotImplementedException();
        }

        public Task DeleteAsync(IdentityUser user)
        {
            throw new NotImplementedException();
        }

        public Task<IdentityUser> FindByIdAsync(int userId)
        {
            throw new NotImplementedException();
        }

        public Task<IdentityUser> FindByNameAsync(string userName)
        {
            throw new NotImplementedException();
        }

        public Task UpdateAsync(IdentityUser user)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}