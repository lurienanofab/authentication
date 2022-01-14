using LNF;
using LNF.CommonTools;
using LNF.Data;
using System;

namespace Authentication.Models
{
    public class PasswordResetUtility
    {
        private readonly IProvider _provider;
        private readonly string _code;

        public IClient Client { get; }
        public IPasswordResetRequest ResetRequest { get; }

        public PasswordResetUtility(IProvider provider, string code)
        {
            _provider = provider;
            _code = code;
            ResetRequest = _provider.Data.Client.GetPasswordResetRequest(_code);
            if (ResetRequest != null)
                Client = _provider.Data.Client.GetClient(ResetRequest.ClientID);
        }

        public bool ConfirmResetCode()
        {
            if (ResetRequest != null)
            {
                if (ResetRequest.ResetDateTime == null)
                {
                    if (Client != null)
                    {
                        if ((DateTime.Now - ResetRequest.RequestDateTime).TotalMinutes < 15)
                        {
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        public bool IsCurrentPassword(string pwd)
        {
            if (Client == null)
                throw new Exception("Cannot check for old password. Client is null.");

            return _provider.Data.Client.AuthUtility().PasswordCheck(Client.ClientID, pwd);
        }

        public bool IsPasswordUserName(string pwd)
        {
            return pwd == Client.UserName;
        }

        public bool Verify()
        {
            return ResetRequest != null && Client != null;
        }
    }
}