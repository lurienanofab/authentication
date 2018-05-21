using LNF;
using LNF.Impl.DependencyInjection.Web;
using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;
using System;
using System.Net;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Routing;

[assembly: OwinStartup(typeof(Authentication.Startup))]

namespace Authentication
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            //allows self signed cert with https
            ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;

            ServiceProvider.Current = IOC.Resolver.GetInstance<ServiceProvider>();

            app.CreatePerOwinContext(ServiceProvider.Current.DataAccess.StartUnitOfWork);

            AreaRegistration.RegisterAllAreas();
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            GlobalConfiguration.Configure(WebApiConfig.Register);

            bool useAspNetIdenity = false;

            if (useAspNetIdenity)
            {
                // Enable the application to use a cookie to store information for the signed in user
                app.UseCookieAuthentication(new CookieAuthenticationOptions
                {
                    AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                    CookieName = "sselAuth.cookie",
                    CookieDomain = ".umich.edu",
                    CookiePath = "/",
                    ReturnUrlParameter = "ReturnUrl",
                    ExpireTimeSpan = TimeSpan.FromHours(8),
                    LoginPath = new PathString("")
                });
            }
        }
    }
}