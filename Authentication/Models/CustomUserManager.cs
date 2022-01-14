using LNF;
using LNF.CommonTools;
using LNF.Data;
using Microsoft.AspNet.Identity;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Authentication.Models
{
    public class CustomUserManager : UserManager<IdentityUser, int>
    {
        protected IProvider Provider { get; }

        public CustomUserManager(IProvider provider) : base(new CustomUserStore())
        {
            Provider = provider;
        }

        public override Task<IdentityResult> CreateAsync(IdentityUser user)
        {
            IdentityResult result;

            if (user.Client != null)
            {
                Provider.Data.Client.Update(user.Client);
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
                var query = Provider.Data.Client.GetAllClients();
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
            IdentityUser result;

            try
            {
                var client = Provider.Data.Client.AuthUtility().Login(userName, password);
                result = new IdentityUser(client);                    
            }
            catch
            {
                result = null;
            }

            // result is null if password check failed...

            return Task.FromResult(result);
        }

        public override Task<IdentityResult> ChangePasswordAsync(int userId, string currentPassword, string newPassword)
        {
            IdentityResult result;

            var auth = Provider.Data.Client.AuthUtility();
            if (auth.LoginPasswordCheck(userId, currentPassword))
            {
                auth.SetPassword(userId, newPassword);
                result = new IdentityResult();
            }
            else
                result = new IdentityResult(string.Format("Current password is incorrect"));

            return Task.FromResult(result);
        }
    }
}