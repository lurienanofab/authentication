using LNF;
using LNF.Impl.DependencyInjection;
using LNF.Web;
using Microsoft.Owin;
using Owin;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Web.Compilation;
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

            var assemblies = BuildManager.GetReferencedAssemblies().Cast<Assembly>().ToArray();

            // setup up dependency injection container
            var webapp = new WebApp();
            var wcc = webapp.GetConfiguration();
            wcc.Context.EnablePropertyInjection();
            wcc.RegisterAllTypes();

            // setup web dependency injection
            webapp.BootstrapMvc(assemblies);

            AreaRegistration.RegisterAllAreas();
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            GlobalConfiguration.Configure(WebApiConfig.Register);

            var provider = webapp.Context.GetInstance<IProvider>();
            ConfigureAuth(app, provider);

            app.UseDataAccess(webapp.Context);
        }
    }
}