using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Authentication.Models
{
    public class PasswordResetModel
    {
        public string UserName { get; set; }
        public string ResetCode { get; set; }
        public string NewPassword { get; set; }
        public string ConfirmPassword { get; set; }
    }
}