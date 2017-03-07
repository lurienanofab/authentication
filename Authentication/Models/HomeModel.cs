using LNF.Cache;
using LNF.Models.Data;
using LNF.Scheduler;
using OnlineServices.Api;
using OnlineServices.Api.Authorization.Credentials;
using System;
using System.Configuration;
using System.Threading.Tasks;
using System.Web;
using System.Web.Security;

namespace Authentication.Models
{
    public class HomeModel
    {
        private const string JWT_COOKIE_NAME = "lnf_token";
        private const string JWT_COOKIE_DOMAIN = ".umich.edu";

        public string UserName { get; set; }
        public string Password { get; set; }
        public string ReturnUrl { get; set; }
        public string ReturnServer { get; set; }

        private HttpCookie CreateJwtCookie(string token)
        {
            var result = new HttpCookie(JWT_COOKIE_NAME, token);
            result.Domain = JWT_COOKIE_DOMAIN;
            result.Path = "/";
            result.HttpOnly = false;
            return result;
        }

        public void LogOut()
        {
            DeleteCookie(CreateJwtCookie(string.Empty));
            FormsAuthentication.SignOut();
        }

        private void DeleteCookie(HttpCookie cookie)
        {
            if (cookie != null)
            {
                cookie.Expires = DateTime.Now.AddDays(-1);
                HttpContext.Current.Response.Cookies.Add(cookie);
            }
        }

        public async Task<LogInResult> LogIn()
        {
            var result = new LogInResult();

            using (var ac = new AuthorizationClient())
            {
                try
                {
                    var auth = await ac.Authorize(new PasswordCredentials(UserName, Password));

                    var client = CacheManager.Current.GetClient(UserName);

                    if (client == null)
                    {
                        result.Reason = "Invalid username or password";
                        result.Success = false;
                        result.Client = null;
                    }
                    else
                    {
                        if (client.ClientActive)
                        {
                            //first create a FormsAuthentication cookie
                            HttpCookie authCookie = FormsAuthentication.GetAuthCookie(client.UserName, true);
                            FormsAuthenticationTicket formInfoTicket = FormsAuthentication.Decrypt(authCookie.Value);
                            FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(formInfoTicket.Version, formInfoTicket.Name, formInfoTicket.IssueDate, formInfoTicket.Expiration, formInfoTicket.IsPersistent, string.Join("|", client.Roles()), formInfoTicket.CookiePath);
                            authCookie.Value = FormsAuthentication.Encrypt(ticket);
                            authCookie.Expires = formInfoTicket.Expiration;

                            HttpContext.Current.Response.Cookies.Add(authCookie);

                            //now create a JWT cookie for the api
                            HttpCookie jwtCookie = CreateJwtCookie(auth.AccessToken);
                            jwtCookie.Expires = DateTime.Now.AddSeconds(auth.ExpiresIn);

                            HttpContext.Current.Response.Cookies.Add(jwtCookie);

                            result.Reason = string.Empty;
                            result.Success = true;
                            result.Client = client;
                        }
                        else
                        {
                            result.Reason = "Client is inactive";
                            result.Success = false;
                            result.Client = client;
                        }
                    }
                }
                catch (Exception ex)
                {
                    string msg = ex.Message;
                    result.Success = false;
                    result.Reason = "Invalid username or password";
                }

                return result;
            }
        }

        public bool RedirectSsl(out string redirectUrl)
        {
            if (HttpContext.Current.Request.IsSecureConnection)
            {
                redirectUrl = HttpContext.Current.Request.Url.ToString();
                return false;
            }

            bool isKiosk = IsKiosk();

            var requireSsl = new { OnKiosk = RequireSSL("OnKiosk"), OnNonKiosk = RequireSSL("OnNonKiosk") };

            redirectUrl = HttpContext.Current.Request.Url.ToString().Replace("http://", "https://");

            if (isKiosk)
                return requireSsl.OnKiosk;
            else
                return requireSsl.OnNonKiosk;
        }

        public string GetRedirectUrl()
        {
            string result = string.Empty;
            GetReturnServer(ref result);
            GetReturnUrl(ref result);
            return result;
        }

        private void GetReturnServer(ref string url)
        {
            if (string.IsNullOrEmpty(ReturnServer))
            {
                url = ConfigurationManager.AppSettings["DefaultReturnServer"];
                url = url.Replace("{self}", HttpContext.Current.Request.Url.Host);
            }
            else
                url = ReturnServer;

            if (!string.IsNullOrEmpty(url))
            {
                if (!url.StartsWith("http://"))
                    url = "http://" + url;

                if (!url.EndsWith("/"))
                    url = url + "/";
            }

            //at this point url will either be an empty string or something like http://<ReturnServer>/ (with a trailing slash)
        }

        private void GetReturnUrl(ref string url)
        {
            string path = ReturnUrl;

            if (string.IsNullOrEmpty(path))
                path = ConfigurationManager.AppSettings["DefaultReturnUrl"];

            if (string.IsNullOrEmpty(url))
            {
                //no server specified
                if (!path.StartsWith("/"))
                    url = "/" + path;
                else
                    url = path;
            }
            else
            {
                //server is specified so it will have a trailing slash
                if (path.StartsWith("/"))
                    path = path.TrimStart('/');

                url += path;
            }

            //at this point we should either have a url like http://<ReturnServer>/<ReturnUrl> or /<ReturnUrl>
        }

        public bool IsKiosk()
        {
            bool result = KioskUtility.IsKiosk() || HttpContext.Current.Request.IsLocal;
            return result;
        }

        public bool RequireSSL(string option)
        {
            string key = string.Format("RequireSSL.{0}", option);
            if (!string.IsNullOrEmpty(ConfigurationManager.AppSettings[key]))
                return bool.Parse(ConfigurationManager.AppSettings[key]);
            return false;
        }
    }

    public class LogInResult
    {
        public bool Success { get; set; }
        public string Reason { get; set; }
        public ClientModel Client { get; set; }
    }
}