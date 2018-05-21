using Authentication.Models;
using LNF.Cache;
using LNF.Models.Data;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace Authentication.Controllers
{
    public class HomeController : Controller
    {
        [HttpGet, Route("")]
        public ActionResult Index(string returnServer = null, string returnUrl = null)
        {
            var model = new HomeModel() { ReturnServer = returnServer, ReturnUrl = returnUrl };
            return LogInView(model);
        }

        [HttpPost, Route("")]
        public ActionResult Index(HomeModel model)
        {
            var result = model.LogIn();

            if (result.Success)
            {
                AddCookies(result.Cookies);
                string redirectUrl = model.GetRedirectUrl();
                return Redirect(redirectUrl);
            }
            else
            {
                Prepare(model);
                ViewBag.ErrorMessage = result.Reason;
                return View(model);
            }
        }

        [Route("signout")]
        public ActionResult SignOut(HomeModel model)
        {
            LogOut();
            return Redirect(model.GetRedirectUrl());
        }

        private void Prepare(HomeModel model)
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

            Prepare(model);

            string url;

            if (model.RedirectSsl(out url))
                return Redirect(url);
            else
            {
                LogOut();
                return View("Index", model);
            }
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

            ClientItem c = null;

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
            DeleteCookie(HomeModel.CreateJwtAuthenticationCookie(string.Empty));
            FormsAuthentication.SignOut();
        }

        private void DeleteCookie(HttpCookie cookie)
        {
            if (cookie != null)
            {
                cookie.Expires = DateTime.Now.AddDays(-1);
                Response.Cookies.Add(cookie);
            }
        }

        private void AddCookies(IEnumerable<HttpCookie> cookies)
        {
            if (cookies != null)
            {
                foreach(var cookie in cookies)
                {
                    Response.Cookies.Add(cookie);
                }
            }
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