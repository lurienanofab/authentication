using System.Collections.Generic;
using System.Linq;

namespace Authentication.Models
{
    public class ClientAppService
    {
        private readonly IEnumerable<ClientApp> _clientApps = new List<ClientApp>()
        {
            new ClientApp()
            {
                Id = "d59f826353454be9a141a2d2cc3370df",
                Name = "Helpdesk",
                Secret = "f9e8cbe5c6ff4d40b254e36cee1b863e",
                RedirectUrl = "http://lnf.eastus.cloudapp.azure.com/helpdesk/api/lnf/oauth2callback.php"
            }
        };

        public ClientApp GetClientAppBytId(string id)
        {
            return _clientApps.FirstOrDefault(x => x.Id == id);
        }
    }
}