using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Configuration;

namespace Authentication
{
    public partial class Startup
    {
        public static OAuthAuthorizationServerOptions OAuthOptions { get; private set; }

        static Startup()
        {
            OAuthOptions = new OAuthAuthorizationServerOptions
            {
                AuthorizeEndpointPath = new PathString("/authorize"),
                TokenEndpointPath = new PathString("/token"),
                ApplicationCanDisplayErrors = true,
                Provider = new OAuthProvider(),
                AuthorizationCodeProvider = new OAuthAuthorizationCodeProvider(),
                RefreshTokenProvider = new OAuthRefreshTokenProvider(),
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(2),
                AllowInsecureHttp = AllowInsecure()
            };
        }

        public void ConfigureAuth(IAppBuilder app)
        {
            bool useAspNetIdenity = true;

            if (useAspNetIdenity)
            {
                // Enable the application to use a cookie to store information for the signed in user
                app.UseCookieAuthentication(new CookieAuthenticationOptions
                {
                    AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                    CookieSecure = CookieSecureOption.SameAsRequest,
                    CookieName = "lnfauth",
                    CookieDomain = ".umich.edu",
                    CookiePath = "/",
                    ReturnUrlParameter = "ReturnUrl",
                    ExpireTimeSpan = TimeSpan.FromHours(24),
                    LoginPath = new PathString("/login")
                });
            }

            // Also use oauth2 bearer authentication to authorize api requests
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());

            app.UseOAuthAuthorizationServer(new OAuthAuthorizationServerOptions
            {
                AuthorizeEndpointPath = new PathString("/authorize"),
                TokenEndpointPath = new PathString("/token"),
                ApplicationCanDisplayErrors = true,
                AllowInsecureHttp = AllowInsecure(),
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(90),

                // Authorization server provider which controls the lifecycle of Authorization Server
                Provider = new OAuthProvider(),

                // Authorization code provider which creates and receives the authorization code.
                AuthorizationCodeProvider = new OAuthAuthorizationCodeProvider(),

                // Refresh token provider which creates and receives refresh token.
                RefreshTokenProvider = new OAuthRefreshTokenProvider(),
            });
        }

        private string GetRedirectUrl(IOwinRequest request)
        {
            string result = string.Empty;
            GetReturnServer(request, ref result);
            GetReturnUrl(request, ref result);
            return result;
        }

        private void GetReturnServer(IOwinRequest request, ref string url)
        {
            var returnServer = request.Query.Get("ReturnServer");
            var host = request.Uri.Host;

            if (string.IsNullOrEmpty(returnServer))
            {
                url = ConfigurationManager.AppSettings["DefaultReturnServer"];
                url = url.Replace("{self}", host);
            }
            else
                url = returnServer;

            if (!string.IsNullOrEmpty(url))
            {
                if (!url.StartsWith("http://"))
                    url = "http://" + url;

                if (!url.EndsWith("/"))
                    url = url + "/";
            }

            //at this point url will either be an empty string or something like http://<ReturnServer>/ (with a trailing slash)
        }

        private void GetReturnUrl(IOwinRequest request, ref string url)
        {
            string path = request.Query.Get("ReturnUrl");

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

        private static bool AllowInsecure()
        {
#if DEBUG
            return true;
#else
            return false;
#endif
        }
    }
}