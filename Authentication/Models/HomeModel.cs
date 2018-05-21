using LNF.Cache;
using LNF.Data;
using LNF.Models.Data;
using LNF.Repository;
using LNF.Scheduler;
using OnlineServices.Api;
using OnlineServices.Api.Authorization.Credentials;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Threading.Tasks;
using System.Web;
using System.Web.Security;

namespace Authentication.Models
{
    public class HomeModel
    {
        public const string JWT_COOKIE_NAME = "lnf_token";
        public const string JWT_COOKIE_DOMAIN = ".umich.edu";

        public string UserName { get; set; }
        public string Password { get; set; }
        public string ReturnUrl { get; set; }
        public string ReturnServer { get; set; }

        public IClientManager ClientManager => DA.Use<IClientManager>();

        public static HttpCookie CreateFormsAuthenticationCookie(string username, string[] roles)
        {
            HttpCookie authCookie = FormsAuthentication.GetAuthCookie(username, true);
            FormsAuthenticationTicket formInfoTicket = FormsAuthentication.Decrypt(authCookie.Value);
            FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(formInfoTicket.Version, formInfoTicket.Name, formInfoTicket.IssueDate, formInfoTicket.Expiration, formInfoTicket.IsPersistent, string.Join("|", roles), formInfoTicket.CookiePath);
            authCookie.Value = FormsAuthentication.Encrypt(ticket);
            authCookie.Expires = formInfoTicket.Expiration;
            return authCookie;
        }

        public static HttpCookie CreateJwtAuthenticationCookie(string token)
        {
            var result = new HttpCookie(JWT_COOKIE_NAME, token)
            {
                Domain = JWT_COOKIE_DOMAIN,
                Path = "/",
                HttpOnly = false
            };

            return result;
        }

        public LogInResult LogIn()
        {
            LogInResult result;

            try
            {
                var client = ClientManager.Login(UserName, Password);

                if (client.ClientActive)
                {
                    var formsCookie = CreateFormsAuthenticationCookie(client.UserName, client.Roles());
                    result = LogInResult.Successful(client, formsCookie);
                }
                else
                {
                    result = LogInResult.Failure("Client is inactive.", client);
                }
            }
            catch (Exception ex)
            {
                result = LogInResult.Failure(ex.Message, null);
            }

            return result;
        }


        public async Task<LogInResult> ApiLogIn()
        {
            using (var ac = new AuthorizationClient())
            {
                LogInResult result;

                try
                {
                    var auth = await ac.Authorize(new PasswordCredentials(UserName, Password));

                    var client = CacheManager.Current.GetClient(UserName);

                    if (client == null)
                    {
                        result = LogInResult.Failure("Invalid username or password.", null);
                    }
                    else
                    {
                        // first create a FormsAuthentication cookie
                        var formsCookie = CreateFormsAuthenticationCookie(client.UserName, client.Roles());

                        // next create a JWT cookie
                        var jwtCookie = CreateJwtAuthenticationCookie(auth.AccessToken);

                        result = LogInResult.Successful(client, formsCookie, jwtCookie);
                    }
                }
                catch (Exception ex)
                {
                    string msg = ex.Message; // should we do something with this?
                    result = LogInResult.Failure("Invalid username or password.", null);
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

    public struct LogInResult
    {
        private LogInResult(bool success, string reason, ClientItem client, params HttpCookie[] cookies)
        {
            Success = success;
            Reason = reason;
            Client = client;
            Cookies = cookies;
        }

        public static LogInResult Successful(ClientItem client, params HttpCookie[] cookies)
        {
            return new LogInResult(true, string.Empty, client, cookies);
        }

        public static LogInResult Failure(string reason, ClientItem client)
        {
            return new LogInResult(false, reason, client, null);
        }

        public bool Success { get; }
        public string Reason { get; }
        public ClientItem Client { get; }
        public IEnumerable<HttpCookie> Cookies { get; }
    }
}