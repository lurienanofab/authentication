using LNF.Models.Data;
using Microsoft.AspNet.Identity;

namespace Authentication.Models
{
    public class IdentityUser : IUser<int>
    {
        public ClientModel Client { get; private set; }

        public IdentityUser(ClientModel client)
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