using Authentication.Models;
using LNF;
using LNF.Data;
using LNF.Web;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace Authentication.Controllers
{
    public class HomeController : Controller
    {
        public const string JWT_COOKIE_NAME = "lnf_token";
        public const string JWT_COOKIE_DOMAIN = ".umich.edu";

        public IProvider Provider { get; private set; }

        public HomeController(IProvider provider)
        {
            Provider = provider;
        }

        public IAuthenticationManager Authentication => HttpContext.GetOwinContext().Authentication;

        [HttpGet, Route("")]
        public ActionResult Index(string returnServer = null, string returnUrl = null)
        {
            ViewBag.PasswordResetRequired = false;
            ViewBag.RequestPasswordReset = false;
            ViewBag.IsHttps = Request.IsSecureConnection;

            var model = new HomeModel
            {
                Provider = Provider,
                ReturnServer = returnServer,
                ReturnUrl = returnUrl,
                CurrentIP = HttpContext.CurrentIP()
            };

            return LogInView(model);
        }

        [HttpPost, Route("")]
        public ActionResult Index(HomeModel model)
        {
            model.Provider = Provider;

            bool passwordResetRequired;
            LogInResult loginResult = PasswordResetRequired(model, out passwordResetRequired);

            ViewBag.PasswordResetRequired = passwordResetRequired;
            ViewBag.RequestPasswordReset = false;
            ViewBag.IsHttps = Request.IsSecureConnection;

            string errmsg = string.Empty;

            if (!passwordResetRequired)
            {
                if (loginResult.Success)
                {
                    AddCookies(CreateFormsAuthenticationCookie(loginResult));

                    var isPersistent = true;

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
                    errmsg = loginResult.Reason;
                }
            }
            else
            {
                AddPasswordResetRequest(loginResult.Client);
            }

            PrepareViewBag(model);

            ViewBag.ErrorMessage = errmsg;

            return View(model);
        }

        [HttpGet, Route("request-password-reset")]
        public ActionResult RequestPasswordReset()
        {
            ViewBag.RequestPasswordReset = true;
            ViewBag.PasswordResetRequired = false;
            ViewBag.PasswordResetError = string.Empty;
            var model = new HomeModel { Provider = Provider };
            PrepareViewBag(model);
            return View("Index", model);
        }

        [HttpPost, Route("request-password-reset")]
        public ActionResult RequestPasswordReset(string username)
        {
            ViewBag.ErrorMessage = string.Empty;

            if (string.IsNullOrEmpty(username))
            {
                ViewBag.RequestPasswordReset = true;
                ViewBag.PasswordResetRequired = false;
                ViewBag.PasswordResetError = "Username is required.";
            }
            else
            {
                var client = Provider.Data.Client.GetClient(username);
                if (client != null)
                {
                    Provider.Data.Client.SetRequirePasswordReset(client.ClientID, true);
                    ViewBag.RequestPasswordReset = false;
                    ViewBag.PasswordResetRequired = true;
                    ViewBag.PasswordResetError = string.Empty;
                    AddPasswordResetRequest(client);
                }
                else
                {
                    ViewBag.RequestPasswordReset = true;
                    ViewBag.PasswordResetRequired = false;
                    ViewBag.PasswordResetError = "Invalid username.";
                }
            }

            var model = new HomeModel { Provider = Provider, UserName = username };

            PrepareViewBag(model);

            return View("Index", model);
        }

        [HttpPost, Route("password-reset")]
        public ActionResult ResetPassword(PasswordResetModel model)
        {
            HomeModel homeModel = new HomeModel { Provider = Provider };

            PrepareViewBag(homeModel);

            ViewBag.ErrorMessage = string.Empty;
            ViewBag.PasswordResetError = string.Empty;
            ViewBag.PasswordResetRequired = false;
            ViewBag.RequestPasswordReset = false;

            bool passwordResetRequired;
            string passwordResetError;

            if (string.IsNullOrEmpty(model.ResetCode))
            {
                passwordResetRequired = true;
                passwordResetError = "Missing reset code.";
            }
            else if (string.IsNullOrEmpty(model.NewPassword))
            {
                passwordResetRequired = true;
                passwordResetError = "Missing new password.";
            }
            else if (string.IsNullOrEmpty(model.NewPassword))
            {
                passwordResetRequired = true;
                passwordResetError = "Missing confirm password.";
            }
            else if (model.NewPassword.Length < 6)
            {
                passwordResetRequired = true;
                passwordResetError = "Password must be at least 6 characters.";
            }
            else if (model.NewPassword != model.ConfirmPassword)
            {
                passwordResetRequired = true;
                passwordResetError = "Passwords do not match.";
            }
            else
            {
                var util = new PasswordResetUtility(Provider, model.ResetCode);

                passwordResetRequired = true;
                passwordResetError = "Invalid reset code. Did you type it correctly?";

                if (util.Verify())
                {
                    if (util.IsCurrentPassword(model.NewPassword))
                    {
                        passwordResetRequired = true;
                        passwordResetError = "You may not reuse your previous password.";
                    }
                    else if (util.IsPasswordUserName(model.NewPassword))
                    {
                        passwordResetRequired = true;
                        passwordResetError = "Your password cannot be the same as your username.";
                    }
                    else if (util.ConfirmResetCode())
                    {
                        Provider.Data.Client.SetPassword(util.Client.ClientID, model.NewPassword);
                        Provider.Data.Client.CompletePasswordReset(util.Client.ClientID, model.ResetCode);
                        Provider.Mail.SendMessage(new LNF.Mail.SendMessageArgs
                        {
                            Caller = "Authentication.Controllers.HomeController.ResetPassword",
                            ClientID = util.Client.ClientID,
                            Attachments = null,
                            Cc = null,
                            From = "lnf-support@umich.edu",
                            Bcc = LNF.CommonTools.SendEmail.DeveloperEmails,
                            DisplayName = "LNF Online Services",
                            To = new[] { util.Client.Email },
                            IsHtml = true,
                            Subject = "LNF password reset complete",
                            Body = "Your LNF Online Services password has been changed successfully. If you did not request a password reset please contact lnf-support@umich.edu immediately."
                        });

                        return RedirectToAction("Index");
                    }
                }
            }

            ViewBag.PasswordResetRequired = passwordResetRequired;
            ViewBag.PasswordResetError = passwordResetError;
            return View("Index", homeModel);
        }

        [Route("signout")]
        public ActionResult SignOut(HomeModel model)
        {
            model.Provider = Provider;

            LogOut();

            return Redirect(model.GetRedirectUrl(Request));
        }

        private void PrepareViewBag(HomeModel model)
        {
            if (string.IsNullOrEmpty(model.CurrentIP))
                model.CurrentIP = HttpContext.CurrentIP();

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

            if (model.RedirectSsl(HttpContext, out string url))
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
                    c = Provider.Data.Client.GetClient(User.Identity.Name);

                    if (c == null)
                        return Json(new { success = false, message = string.Format("no client found for '{0}'", User.Identity.Name) });

                    //success!
                    if (string.IsNullOrEmpty(callback))
                        return Json(GetAuthCheckResponse(true, string.Empty, User, c), JsonRequestBehavior.AllowGet);
                    else
                        return Jsonp(GetAuthCheckResponse(true, string.Empty, User, c), callback);
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
                    c = Provider.Data.Client.GetClient(ticket.Name);

                    if (c == null)
                        return Json(new { success = false, message = string.Format("no client found for '{0}'", ticket.Name) });

                    //success!
                    if (string.IsNullOrEmpty(callback))
                        return Json(GetAuthCheckResponse(true, string.Empty, ticket, c));
                    else
                        return Jsonp(GetAuthCheckResponse(true, string.Empty, ticket, c), callback);
                }

                if (string.IsNullOrEmpty(callback))
                    return Json(new { success = false, message = "no username found", authenticated = false, username = "" });
                else
                    return Jsonp(new { success = false, message = "no username found", authenticated = false, username = "" }, callback);
            }
        }

        private static object GetAuthCheckResponse(bool success, string message, IPrincipal user, IClient c)
        {
            return new
            {
                success,
                message,
                authenticated = user.Identity.IsAuthenticated,
                clientId = c.ClientID,
                username = user.Identity.Name,
                roles = c.Roles(),
                lastName = c.LName,
                firstName = c.FName,
                middleName = c.MName,
                displayName = c.DisplayName,
                privs = (int)c.Privs,
                email = c.Email
            };
        }

        private static object GetAuthCheckResponse(bool success, string message, FormsAuthenticationTicket ticket, IClient c)
        {
            return new
            {
                success,
                message,
                authenticated = !ticket.Expired,
                username = ticket.Name,
                roles = c.Roles(),
                lastName = c.LName,
                firstName = c.FName,
                email = c.Email,
                expiration = ticket.Expiration,
                expired = ticket.Expired
            };
        }

        private IHtmlString GetKioskMessage()
        {
            string[] splitter = Request.UserHostAddress.Split('.');

            TagBuilder builder = new TagBuilder("div");

            builder.AddCssClass("kiosk-message-text");

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
                string[] roles = GetRoles(loginResult.Client);
                HttpCookie authCookie = FormsAuthentication.GetAuthCookie(username, true);
                FormsAuthenticationTicket formInfoTicket = FormsAuthentication.Decrypt(authCookie.Value);
                FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(formInfoTicket.Version, formInfoTicket.Name, formInfoTicket.IssueDate, formInfoTicket.Expiration, formInfoTicket.IsPersistent, string.Join("|", roles), formInfoTicket.CookiePath);
                authCookie.Value = FormsAuthentication.Encrypt(ticket);
                authCookie.Expires = formInfoTicket.Expiration;
                return authCookie;
            }

            return null;
        }

        private string[] GetRoles(IClient client)
        {
            var privs = Provider.Data.Client.GetPrivs();
            return privs.Where(x => (x.PrivFlag & client.Privs) > 0).Select(x => x.PrivType).ToArray();
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

        private LogInResult PasswordResetRequired(HomeModel model, out bool result)
        {
            var client = Provider.Data.Client.GetClient(model.UserName);

            if (client == null)
            {
                result = false;
                return LogInResult.Failure("Incorrect username or password.", client);
            }

            if (!client.ClientActive)
            {
                result = false;
                return LogInResult.Failure("Client is inactive.", client);
            }

            if (Provider.Data.Client.GetRequirePasswordReset(client.ClientID))
            {
                result = true;
                return LogInResult.Failure("Password reset required.", client);
            }

            result = false;
            return model.LogIn();
        }

        private void AddPasswordResetRequest(IClient client)
        {
            IPasswordResetRequest req = Provider.Data.Client.AddPasswordResetRequest(client.ClientID);
            Provider.Mail.SendMessage(new LNF.Mail.SendMessageArgs
            {
                Caller = "Authentication.Controllers.HomeController.Index",
                ClientID = client.ClientID,
                Attachments = null,
                Bcc = LNF.CommonTools.SendEmail.DeveloperEmails,
                To = new[] { client.Email },
                From = "lnf-support@umich.edu",
                DisplayName = "LNF Online Services",
                IsHtml = true,
                Cc = null,
                Subject = $"LNF password reset request [{DateTime.Now:yyyy-MM-dd HH:mm:ss}]",
                Body = $"Hello {client.FName} {client.LName},<br><br>You have requested a password reset for LNF Online Services. Please use this code to complete the reset: <b>{req.ResetCode}</b> (case sensitive).<br><br>This code expires in 15 minutes. If you did not make this request please contact lnf-support@umich.edu immediately."
            });
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