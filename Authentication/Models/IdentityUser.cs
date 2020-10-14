using LNF.Data;
using Microsoft.AspNet.Identity;

namespace Authentication.Models
{
    public class IdentityUser : IUser<int>
    {
        public IClient Client { get; private set; }

        public IdentityUser(IClient client)
        {
            Client = client;
        }

        public int Id
        {
            get { return Client.ClientID; }
        }

        public string UserName
        {
            get
            {
                return Client.UserName;
            }
            set
            {
                //cannot be changed
            }
        }

        public string FirstName { get { return Client.FName; } }

        public string LastName { get { return Client.LName; } }
    }
}