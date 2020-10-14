using LNF;
using LNF.Authorization.Credentials;
using LNF.Data;
using LNF.Scheduler;
using OnlineServices.Api.Authorization;
using System;
using System.Configuration;
using System.Web;

namespace Authentication.Models
{
    public class HomeModel
    {
        public IProvider Provider { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public string ReturnUrl { get; set; }
        public string ReturnServer { get; set; }
        public string CurrentIP { get; set; }

        public LogInResult LogIn()
        {
            LogInResult result;

            try
            {
                var client = Provider.Data.Client.Login(UserName, Password);

                if (client.ClientActive)
                    result = LogInResult.Successful(client);
                else
                    result = LogInResult.Failure("Client is inactive.", client);
            }
            catch (Exception ex)
            {
                result = LogInResult.Failure(ex.Message, null);
            }

            return result;
        }


        public LogInResult ApiLogIn()
        {
            var svc = new AuthorizationService();

            LogInResult result;

            try
            {
                var auth = svc.Authorize(new PasswordCredentials(UserName, Password));

                var client = Provider.Data.Client.GetClient(UserName);

                if (client == null)
                {
                    result = LogInResult.Failure("Invalid username or password.", null);
                }
                else
                {
                    // first create a FormsAuthentication cookie
                    //var formsCookie = CreateFormsAuthenticationCookie(client.UserName, client.Roles());

                    // next create a JWT cookie
                    //var jwtCookie = CreateJwtAuthenticationCookie(auth.AccessToken);

                    result = LogInResult.Successful(client);
                }
            }
            catch (Exception ex)
            {
                string msg = ex.Message; // should we do something with this?
                result = LogInResult.Failure("Invalid username or password.", null);
            }

            return result;
        }

        public bool RedirectSsl(HttpContextBase context, out string redirectUrl)
        {
            if (context.Request.IsSecureConnection)
            {
                // Nothing needs to be done. The request is already so redirecting is not necessary.
                redirectUrl = context.Request.Url.ToString();
                return false;
            }

            // At this point the request is http (not ssl).
            // Now we check if a redirect to https is needed based on web.config.

            // get the settings from web.config
            var requireSsl = new
            {
                OnKiosk = RequireSSL("OnKiosk"),
                OnNonKiosk = RequireSSL("OnNonKiosk")
            };

            // if a redirect is necessary it will be to https
            redirectUrl = context.Request.Url.ToString().Replace("http://", "https://");

            // use the appropriate setting depending on if the request is coming from a kiosk or not.
            if (IsKiosk())
                return requireSsl.OnKiosk;
            else
                return requireSsl.OnNonKiosk;
        }

        /// <summary>
        /// Gets the redirect url based on the current ReturnServer and ReturnUrl properties. A full url (i.e https://host/path) is always returned. The scheme (http or http) is determined by the current request.
        /// </summary>
        public string GetRedirectUrl(HttpRequestBase request)
        {
            string result = string.Empty;
            GetReturnServer(request, ref result);
            GetReturnUrl(ref result);
            return result;
        }

        private void GetReturnServer(HttpRequestBase request, ref string url)
        {
            string host;

            if (string.IsNullOrEmpty(ReturnServer))
            {
                host = GetDefaultReturnServer();
                host = host.Replace("{self}", request.Url.Host);
            }
            else
                host = ReturnServer;

            UriBuilder builder = new UriBuilder(host);

            if (request.IsSecureConnection)
            {
                builder.Scheme = Uri.UriSchemeHttps;
                builder.Port = 443;
            }
            else
            {
                builder.Scheme = Uri.UriSchemeHttp;
                builder.Port = 80;
            }

            url = builder.Uri.ToString();

            //at this point url be something like http(s)://<ReturnServer>/ (with a trailing slash)
        }

        private void GetReturnUrl(ref string url)
        {
            string path = ReturnUrl;

            if (string.IsNullOrEmpty(path))
                path = ConfigurationManager.AppSettings["DefaultReturnUrl"];

            // url will always have a trailing slash so remove it from path
            path = path.TrimStart('/');

            var builder = new UriBuilder(url + path);

            url = builder.Uri.ToString();

            //at this point we should either have a url like http://<ReturnServer>/<ReturnUrl> or /<ReturnUrl>
        }

        private string GetDefaultReturnServer()
        {
            var result = ConfigurationManager.AppSettings["DefaultReturnServer"];
            if (string.IsNullOrEmpty(result))
                result = "{self}";
            return result;
        }

        public bool IsKiosk()
        {
            bool result = Kiosks.Create(Provider.Scheduler.Kiosk).IsKiosk(CurrentIP);
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
        private LogInResult(bool success, string reason, IClient client)
        {
            Success = success;
            Reason = reason;
            Client = client;
        }

        public static LogInResult Successful(IClient client)
        {
            return new LogInResult(true, string.Empty, client);
        }

        public static LogInResult Failure(string reason, IClient client)
        {
            return new LogInResult(false, reason, client);
        }

        public bool Success { get; }
        public string Reason { get; }
        public IClient Client { get; }
    }
}