using LNF;
using LNF.Cache;
using LNF.Models.Data;
using LNF.Repository;
using LNF.Repository.Data;
using Microsoft.AspNet.Identity;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Authentication.Models
{
    public class CustomUserManager : UserManager<IdentityUser, int>
    {
        public CustomUserManager() : base(new CustomUserStore()) { }

        public override Task<IdentityResult> CreateAsync(IdentityUser user)
        {
            IdentityResult result = null;

            if (user.Client != null)
            {
                ServiceProvider.Current.Data.ClientManager.Update(user.Client);
                result = new IdentityResult();
            }
            else
                result = new IdentityResult("Client is null");

            return Task.FromResult(result);
        }

        public override IQueryable<IdentityUser> Users
        {
            get
            {
                var query = DA.Current.Query<ClientInfo>().CreateModels<IClient>();
                var result = query.Select(x => new IdentityUser(x)).AsQueryable();
                return result;
            }
        }

        public override Task<ClaimsIdentity> CreateIdentityAsync(IdentityUser user, string authenticationType)
        {
            ClaimsIdentity ident = new ClaimsIdentity(authenticationType);

            ident.AddClaim(new Claim(ClaimTypes.Name, user.UserName));
            ident.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Client.ClientID.ToString()));
            ident.AddClaim(new Claim(ClaimTypes.Surname, user.Client.LName));
            ident.AddClaim(new Claim(ClaimTypes.GivenName, user.Client.FName));
            ident.AddClaim(new Claim(ClaimTypes.Email, user.Client.Email));

            foreach (string role in user.Client.Roles())
                ident.AddClaim(new Claim(ClaimTypes.Role, role));

            return Task.FromResult(ident);
        }

        public override Task<IdentityUser> FindAsync(string userName, string password)
        {
            IdentityUser result = null;

            var client = CacheManager.Current.GetClient(userName);

            if (ServiceProvider.Current.Data.ClientManager.CheckPassword(client.ClientID, password))
                result = new IdentityUser(client);

            // result is null if password check failed...

            return Task.FromResult(result);
        }

        public override Task<IdentityResult> ChangePasswordAsync(int userId, string currentPassword, string newPassword)
        {
            IdentityResult result = null;

            Client client = DA.Current.Single<Client>(userId);

            if (client == null)
                result = new IdentityResult(string.Format("Cannot find record with ClientID = {0}", userId));

            if (client.CheckPassword(currentPassword))
            {
                client.SetPassword(newPassword);
                result = new IdentityResult();
            }
            else
                result = new IdentityResult(string.Format("Current password is incorrect"));

            return Task.FromResult(result);
        }
    }
}