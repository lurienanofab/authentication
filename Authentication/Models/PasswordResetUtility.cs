using LNF;
using LNF.CommonTools;
using LNF.Data;
using LNF.Repository;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Web;

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

            var sql = "SELECT [Password], PasswordHash FROM sselData.dbo.Client WHERE ClientID = @ClientID";

            var dt = DefaultDataCommand.Create(CommandType.Text)
                .Param("ClientID", Client.ClientID)
                .FillDataTable(sql);

            if (dt.Rows.Count == 0)
                throw new ItemNotFoundException("Client", "ClientID", Client.ClientID);

            var currentPwd = dt.Rows[0].Field<string>("Password");
            var hash = dt.Rows[0].Field<string>("PasswordHash");

            if (currentPwd.Length < 64)
            {
                // handle old password
                var enc = new Encryption();
                var encPwd = enc.EncryptText(pwd);
                return currentPwd == encPwd;
            }
            else
            {
                // handle new password
                return _provider.Data.Client.CheckPassword(Client.ClientID, pwd);
            }
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