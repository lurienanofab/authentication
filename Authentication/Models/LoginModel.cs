using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Authentication.Models
{
    public class LoginModel
    {
        public string UserName { get; set; }
        public string Password { get; set; }
        public string ReturnUrl { get; set; }
        public bool IsPersistent { get; set; }

        public string GetReturnUrl()
        {
            if (string.IsNullOrEmpty(ReturnUrl))
                return "/";
            else
                return ReturnUrl;
        }
    }
}