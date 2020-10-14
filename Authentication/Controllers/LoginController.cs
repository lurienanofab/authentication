using Authentication.Models;
using LNF;
using LNF.Scheduler;
using LNF.Web;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace Authentication.Controllers
{
    public class LoginController : Controller
    {
        private CustomUserManager _UserManager;

        public ContextHelper Helper { get; private set; }

        public IProvider Provider { get; }

        public LoginController(IProvider provider)
        {
            Provider = provider;
        }

        protected override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            Helper = new ContextHelper(HttpContext, Provider);
        }

        public CustomUserManager UserManager
        {
            get
            {
                if (_UserManager == null)
                    _UserManager = new CustomUserManager(Provider);
                return _UserManager;
            }
        }

        [Route("v2")]
        public ActionResult Index(LoginModel model)
        {
            model.Provider = Provider;

            HttpContext.GetOwinContext().Authentication.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            HttpContext.Response.Cookies.Add(new HttpCookie("sselAuth.Cookie", null) { Path = "/", Domain = ".umich.edu", Expires = DateTime.Now.AddDays(-1) });

            ViewBag.KioskMessage = GetKioskMessage();

            return View(model);
        }

        [HttpPost, Route("v2/auth")]
        public async Task<ActionResult> SignInAsync(LoginModel model)
        {
            model.Provider = Provider;

            IdentityUser user = await UserManager.FindAsync(model.UserName, model.Password);

            if (user == null)
            {
                // password check failed
                ViewBag.ErrorMessage = GetErrorMessage("Invalid username or password", false);
                ViewBag.MobileErrorMessage = GetErrorMessage("Invalid username or password", true);
                return View("Index", model);
            }

            var identity = await UserManager.CreateIdentityAsync(user, DefaultAuthenticationTypes.ApplicationCookie);

            Request.GetOwinContext().Authentication.SignIn(new AuthenticationProperties() { IsPersistent = true }, identity);

            return Redirect(model.GetReturnUrl());
            //return RedirectToAction("AuthCheck", "Login");
        }

        [Route("v2/authcheck")]
        public ActionResult AuthCheck()
        {
            var ident = (ClaimsIdentity)User.Identity;
            return Json(new
            {
                UserName = ident.Name,
                ClientID = ident.GetUserId<int>(),
                LastName = ident.Claims.First(x => x.Type == ClaimTypes.Surname).Value,
                FirstName = ident.Claims.First(x => x.Type == ClaimTypes.GivenName).Value,
                Email = ident.Claims.First(x => x.Type == ClaimTypes.Email).Value,
                Roles = ident.Claims.Where(x => x.Type == ClaimTypes.Role).Select(x => x.Value).ToArray()
            }, JsonRequestBehavior.AllowGet);
        }

        public IHtmlString GetErrorMessage(string err, bool mobile)
        {
            TagBuilder builder = new TagBuilder("div");

            if (mobile)
            {
                builder.AddCssClass("mobile-error-message");
                builder.AddCssClass("visible-xs-block");
                builder.AddCssClass("alert");
                builder.AddCssClass("alert-danger");
                builder.Attributes.Add("role", "alert");
            }
            else
            {
                builder.AddCssClass("error-message");
                builder.AddCssClass("visible-sm-block");
                builder.AddCssClass("visible-md-block");
                builder.AddCssClass("visible-lg-block");
                builder.AddCssClass("alert");
                builder.AddCssClass("alert-danger");
                builder.Attributes.Add("role", "alert");
            }

            builder.SetInnerText(err);

            return new HtmlString(builder.ToString());
        }

        public string GetKioskMessage()
        {
            var result = string.Empty;

            if (Helper.IsKiosk())
            {
                var splitter = Request.UserHostAddress.Split('.');
                result = string.Format("Kiosk #{0}", splitter.LastOrDefault() ?? Request.UserHostAddress);
            }

            return result;
        }
    }
}