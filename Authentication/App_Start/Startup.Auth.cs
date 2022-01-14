using LNF;
using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Configuration;
using System.Threading.Tasks;
using System.Web;

namespace Authentication
{
    public partial class Startup
    {
        public static OAuthAuthorizationServerOptions GetServerOptions(IProvider provider)
        {
            return new OAuthAuthorizationServerOptions
            {
                AuthorizeEndpointPath = new PathString("/oauth/authorize"),
                TokenEndpointPath = new PathString("/oauth/token"),
                ApplicationCanDisplayErrors = true,
                Provider = new OAuthProvider(provider),
                AuthorizationCodeProvider = new OAuthAuthorizationCodeProvider(),
                RefreshTokenProvider = new OAuthRefreshTokenProvider(),
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(2),
                AllowInsecureHttp = AllowInsecure()
            };
        }

        public void ConfigureAuth(IAppBuilder app, IProvider provider)
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

            // Checks the querystring for the access_token variable and adds an Authorization header if found.
            // This must come before app.UseOAuthBearerAuthentication(...) is called.
            app.Use(OAuthQueryStringAccessTokenAuthentication);

            // Also use oauth2 bearer authentication to authorize api requests
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());

            app.UseOAuthAuthorizationServer(new OAuthAuthorizationServerOptions
            {
                AuthorizeEndpointPath = new PathString("/oauth/authorize"),
                TokenEndpointPath = new PathString("/oauth/token"),
                ApplicationCanDisplayErrors = true,
                AllowInsecureHttp = AllowInsecure(),
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(90),

                // Authorization server provider which controls the lifecycle of Authorization Server
                Provider = new OAuthProvider(provider),

                // Authorization code provider which creates and receives the authorization code.
                AuthorizationCodeProvider = new OAuthAuthorizationCodeProvider(),

                // Refresh token provider which creates and receives refresh token.
                RefreshTokenProvider = new OAuthRefreshTokenProvider(),
            });
        }

        private static bool AllowInsecure()
        {
            // must be true to allow http redirects (e.g. http://lnf-wiki.eecs.umich.edu)
            return true;
        }

        private async Task OAuthQueryStringAccessTokenAuthentication(IOwinContext context, Func<Task> next)
        {
            if (context.Request.QueryString.HasValue)
            {
                if (string.IsNullOrWhiteSpace(context.Request.Headers.Get("Authorization")))
                {
                    var queryString = HttpUtility.ParseQueryString(context.Request.QueryString.Value);
                    string token = queryString.Get("access_token");

                    if (!string.IsNullOrWhiteSpace(token))
                    {
                        context.Request.Headers.Add("Authorization", new[] { string.Format("Bearer {0}", token) });
                    }
                }
            }

            await next.Invoke();
        }
    }
}