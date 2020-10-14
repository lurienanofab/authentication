using LNF;
using LNF.Web;
using Microsoft.Owin;
using Owin;
using System.Net;
using System.Reflection;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Routing;

[assembly: OwinStartup(typeof(Authentication.Startup))]

namespace Authentication
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            //allows self signed cert with https
            ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;

            WebApp.Current.BootstrapMvc(new[] { Assembly.GetExecutingAssembly() });

            AreaRegistration.RegisterAllAreas();
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            GlobalConfiguration.Configure(WebApiConfig.Register);

            var provider = WebApp.Current.GetInstance<IProvider>();
            ConfigureAuth(app, provider);

            app.UseDataAccess();
        }
    }
}