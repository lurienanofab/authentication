using Authentication.Models;
using LNF.Cache;
using LNF.Models.Data;
using LNF.Repository;
using LNF.Repository.Data;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace Authentication.Controllers
{
    public class HomeController : Controller
    {
        public const string JWT_COOKIE_NAME = "lnf_token";
        public const string JWT_COOKIE_DOMAIN = ".umich.edu";

        public IAuthenticationManager Authentication => HttpContext.GetOwinContext().Authentication;

        [HttpGet, Route("")]
        public ActionResult Index(string returnServer = null, string returnUrl = null)
        {
            var model = new HomeModel() { ReturnServer = returnServer, ReturnUrl = returnUrl };
            return LogInView(model);
        }

        [HttpPost, Route("")]
        public ActionResult Index(HomeModel model)
        {
            var loginResult = model.LogIn();

            if (loginResult.Success)
            {
                AddCookies(CreateFormsAuthenticationCookie(loginResult));

                var isPersistent = true; //!string.IsNullOrEmpty(Request.Form.Get("isPersistent"));

                var claims = new List<Claim> { new Claim(ClaimsIdentity.DefaultNameClaimType, model.UserName) };
                claims.AddRange(loginResult.Client.Roles().Select(x => new Claim(ClaimsIdentity.DefaultRoleClaimType, x)));

                Authentication.SignIn(
                    new AuthenticationProperties { IsPersistent = isPersistent },
                    new ClaimsIdentity(claims, DefaultAuthenticationTypes.ApplicationCookie));

                string redirectUrl = model.GetRedirectUrl(Request);
                return Redirect(redirectUrl);
            }
            else
            {
                ViewBag.ErrorMessage = loginResult.Reason;
            }

            PrepareViewBag(model);
            return View(model);
        }

        [Route("signout")]
        public ActionResult SignOut(HomeModel model)
        {
            LogOut();
            return Redirect(model.GetRedirectUrl(Request));
        }

        private void PrepareViewBag(HomeModel model)
        {
            ViewBag.ErrorMessage = string.Empty;
            ViewBag.KioskMessage = string.Empty;

            ViewBag.MobileErrorMessage = string.Empty;
            ViewBag.MobileKioskMessage = string.Empty;

            if (model.IsKiosk())
            {
                ViewBag.KioskMessage = GetKioskMessage();
            }
        }

        private ActionResult LogInView(HomeModel model)
        {
            //Assume the user is not trying to log in at this point.
            //Either returns the Index view or redirects to https if ssl is required.

            if (model.RedirectSsl(out string url))
                return Redirect(url);

            LogOut();
            PrepareViewBag(model);
            return View("Index", model);
        }

        [Route("authcookie")]
        public ActionResult AuthCookie(string ReturnUrl = "", string callback = "")
        {
            var cookie = Request.Cookies[FormsAuthentication.FormsCookieName];

            if (cookie == null)
                ViewBag.CookieValue = string.Empty;
            else
                ViewBag.CookieValue = cookie.Value;

            ViewBag.ReturnUrl = ReturnUrl;

            if (!string.IsNullOrEmpty(callback))
            {
                string json = JsonConvert.SerializeObject(new { cookieValue = ViewBag.CookieValue });
                return Content(callback + "(" + json + ")", "application/javascript");
            }
            else
                return View();
        }

        private ActionResult Jsonp(object obj, string callback)
        {
            string json = JsonConvert.SerializeObject(obj);
            return Content(callback + "(" + json + ")", "application/javascript");
        }

        [Route("authcheck")]
        public ActionResult AuthCheck(string cookieValue = "", string callback = "")
        {
            //Two methods of checking auth are provided:
            //1) No cookieValue is passed and GET requests are allowed. This is for client-side checking from the browser (i.e. javascript)
            //2) A value is passed for cookieValue and only POST requests are allowed. This is for server-side checking from .NET, PHP, etc. (note: the server side application must be able to see the auth cookie to get it's value - in other words on the same domain)

            IClient c = null;

            if (string.IsNullOrEmpty(cookieValue))
            {
                if (!string.IsNullOrEmpty(User.Identity.Name))
                {
                    c = CacheManager.Current.GetClient(User.Identity.Name);

                    if (c == null)
                        return Json(new { success = false, message = string.Format("no client found for '{0}'", User.Identity.Name) });

                    //success!
                    if (string.IsNullOrEmpty(callback))
                        return Json(new { success = true, message = "", authenticated = User.Identity.IsAuthenticated, clientId = c.ClientID, username = User.Identity.Name, roles = c.Roles(), lastName = c.LName, firstName = c.FName, middleName = c.MName, privs = (int)c.Privs, email = c.Email }, JsonRequestBehavior.AllowGet);
                    else
                        return Jsonp(new { success = true, message = "", authenticated = User.Identity.IsAuthenticated, clientId = c.ClientID, username = User.Identity.Name, roles = c.Roles(), lastName = c.LName, firstName = c.FName, middleName = c.MName, privs = (int)c.Privs, email = c.Email }, callback);
                }

                if (string.IsNullOrEmpty(callback))
                    return Json(new { success = false, message = "no username found", authenticated = User.Identity.IsAuthenticated, username = User.Identity.Name }, JsonRequestBehavior.AllowGet);
                else
                    return Jsonp(new { success = false, message = "no username found", authenticated = User.Identity.IsAuthenticated, username = User.Identity.Name }, callback);
            }
            else
            {
                var ticket = FormsAuthentication.Decrypt(cookieValue);

                if (!string.IsNullOrEmpty(ticket.Name))
                {
                    c = CacheManager.Current.GetClient(ticket.Name);

                    if (c == null)
                        return Json(new { success = false, message = string.Format("no client found for '{0}'", ticket.Name) });

                    //success!
                    if (string.IsNullOrEmpty(callback))
                        return Json(new { success = true, message = "", authenticated = !ticket.Expired, username = ticket.Name, roles = c.Roles(), lastName = c.LName, firstName = c.FName, email = c.Email, expiration = ticket.Expiration, expired = ticket.Expired });
                    else
                        return Jsonp(new { success = true, message = "", authenticated = !ticket.Expired, username = ticket.Name, roles = c.Roles(), lastName = c.LName, firstName = c.FName, email = c.Email, expiration = ticket.Expiration, expired = ticket.Expired }, callback);
                }

                if (string.IsNullOrEmpty(callback))
                    return Json(new { success = false, message = "no username found", authenticated = false, username = "" });
                else
                    return Jsonp(new { success = false, message = "no username found", authenticated = false, username = "" }, callback);
            }
        }

        [HttpGet, Route("authorize")]
        public async Task<ActionResult> Authorize()
        {
            // Set by OAuthProvider to something other than 200 if the request is invalid, for example if client_id is missing from querystring.
            if (Response.StatusCode != 200)
                return View("AuthorizeError");

            //var userName = ticket.Identity.Name
            var userName = User.Identity.Name;

            var c = DA.Current.Query<Client>().FirstOrDefault(x => x.UserName == userName);

            if (c != null)
                ViewBag.DisplayName = $"{c.FName} {c.LName}";
            else
                ViewBag.DisplayName = User.Identity.Name;

            var clientAppService = new ClientAppService();
            var clientApp = clientAppService.GetClientAppBytId(Request.QueryString["client_id"]);

            return await Task.FromResult(View(clientApp));
        }

        [HttpPost, Route("authorize")]
        public async Task<ActionResult> Authorize(string grant = null, string login = null)
        {
            if (Response.StatusCode != 200)
                return View("AuthorizeError");

            if (!string.IsNullOrEmpty(grant))
            {
                //var ticket = await authentication.AuthenticateAsync("Application");
                //var identity = ticket?.Identity;
                var identity = (FormsIdentity)User.Identity;

                if (identity != null)
                {
                    var scopes = (Request.QueryString.Get("scope") ?? "").Split(' ');
                    var claimsIdentity = new ClaimsIdentity(identity.Claims, "Bearer", identity.NameClaimType, identity.RoleClaimType);

                    foreach (var scope in scopes)
                        claimsIdentity.AddClaim(new Claim("urn:oauth:scope", scope));

                    Authentication.SignIn(claimsIdentity);
                }
            }
            else if (!string.IsNullOrEmpty(login))
            {
                FormsAuthentication.SignOut();
                Response.Redirect(FormsAuthentication.LoginUrl);
                return new HttpUnauthorizedResult();
            }

            var clientAppService = new ClientAppService();
            var clientApp = clientAppService.GetClientAppBytId(Request.QueryString["client_id"]);

            return await Task.FromResult(View(clientApp));
        }

        private IHtmlString GetKioskMessage()
        {
            string[] splitter = Request.UserHostAddress.Split('.');

            TagBuilder builder = new TagBuilder("div");

            builder.AddCssClass("kiosk-message");

            builder.SetInnerText(string.Format("Kiosk #{0}", splitter.Last() ?? Request.UserHostAddress));

            return new HtmlString(builder.ToString());
        }

        private void LogOut()
        {
            DeleteCookies(CreateJwtAuthenticationCookie(string.Empty));
            FormsAuthentication.SignOut();
            Authentication.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
        }

        private void DeleteCookies(params HttpCookie[] cookies)
        {
            if (cookies != null)
            {
                foreach (var cookie in cookies.Where(x => x != null))
                {
                    cookie.Expires = DateTime.Now.AddDays(-1);
                    Response.Cookies.Add(cookie);
                }
            }
        }

        private void AddCookies(params HttpCookie[] cookies)
        {
            if (cookies != null)
            {
                foreach (var cookie in cookies.Where(x => x != null))
                {
                    Response.Cookies.Add(cookie);
                }
            }
        }

        private HttpCookie CreateFormsAuthenticationCookie(LogInResult loginResult)
        {
            if (loginResult.Success)
            {
                string username = loginResult.Client.UserName;
                string[] roles = loginResult.Client.Roles();
                HttpCookie authCookie = FormsAuthentication.GetAuthCookie(username, true);
                FormsAuthenticationTicket formInfoTicket = FormsAuthentication.Decrypt(authCookie.Value);
                FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(formInfoTicket.Version, formInfoTicket.Name, formInfoTicket.IssueDate, formInfoTicket.Expiration, formInfoTicket.IsPersistent, string.Join("|", roles), formInfoTicket.CookiePath);
                authCookie.Value = FormsAuthentication.Encrypt(ticket);
                authCookie.Expires = formInfoTicket.Expiration;
                return authCookie;
            }

            return null;
        }

        private HttpCookie CreateJwtAuthenticationCookie(string token)
        {
            var result = new HttpCookie(JWT_COOKIE_NAME, token)
            {
                Domain = JWT_COOKIE_DOMAIN,
                Path = "/",
                HttpOnly = false
            };

            return result;
        }
    }

    public class LogInActionResult : ActionResult
    {
        private ActionResult _action;

        public LogInResult LogInResult { get; private set; }

        public LogInActionResult(LogInResult result, ActionResult action)
        {
            _action = action;
            LogInResult = result;
        }

        public override void ExecuteResult(ControllerContext context)
        {
            _action.ExecuteResult(context);
        }
    }
}