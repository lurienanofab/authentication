using Authentication.Models;
using LNF;
using LNF.Impl.Repository.Data;
using Microsoft.Owin.Security;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace Authentication.Controllers
{
    public class OAuthController : Controller
    {
        public IAuthenticationManager Authentication => HttpContext.GetOwinContext().Authentication;

        public IProvider Provider { get; }

        public OAuthController(IProvider provider)
        {
            Provider = provider;
        }

        [Authorize, HttpGet, Route("oauth/authorize")]
        public async Task<ActionResult> Authorize()
        {
            // Set by OAuthProvider to something other than 200 if the request is invalid, for example if client_id is missing from querystring.
            if (Response.StatusCode != 200)
            {
                return View("AuthorizeError");
            }

            var userName = User.Identity.Name;

            var c = Provider.DataAccess.Session.Query<Client>().FirstOrDefault(x => x.UserName == userName);

            if (c != null)
                ViewBag.DisplayName = $"{c.FName} {c.LName}";
            else
                ViewBag.DisplayName = User.Identity.Name;

            return await SignIn();

            //return await Task.FromResult(View(clientApp));
        }

        [Authorize, HttpPost, Route("oauth/authorize")]
        public async Task<ActionResult> Authorize(string grant = null, string login = null)
        {
            if (Response.StatusCode != 200)
                return View("AuthorizeError");

            if (!string.IsNullOrEmpty(login))
                return SignOut();

            if (!string.IsNullOrEmpty(grant))
                return await SignIn();
            else
                throw new Exception("Missing required parameter: grant");
        }

        private async Task<ActionResult> SignIn()
        {
            var identity = (ClaimsIdentity)User.Identity;

            if (identity != null)
            {
                var scopes = (Request.QueryString.Get("scope") ?? "").Split(' ');
                var claimsIdentity = new ClaimsIdentity(identity.Claims, "Bearer", identity.NameClaimType, identity.RoleClaimType);

                foreach (var scope in scopes)
                    claimsIdentity.AddClaim(new Claim("urn:oauth:scope", scope));

                Authentication.SignIn(claimsIdentity);
            }

            var clientAppService = new ClientAppRepository();
            var clientApp = clientAppService.GetClientAppBytId(Request.QueryString["client_id"]);

            return await Task.FromResult(View("Authorize", clientApp));
        }

        private ActionResult SignOut()
        {
            FormsAuthentication.SignOut();
            Response.Redirect(FormsAuthentication.LoginUrl);
            return new HttpUnauthorizedResult();
        }
    }
}