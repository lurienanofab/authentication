using Authentication.Models;
using LNF;
using LNF.Models.Data;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Authentication
{
    public class OAuthProvider : OAuthAuthorizationServerProvider
    {
        //private readonly UserService userService;
        private readonly ClientAppService clientAppService;
        private readonly IClientManager clientManager;

        public OAuthProvider()
        {
            //userService = new UserService();
            clientAppService = new ClientAppService();
            clientManager = ServiceProvider.Current.Data.Client;
        }

        public override Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            return Task.Factory.StartNew(() =>
            {
                var client = clientAppService.GetClientAppBytId(context.ClientId);

                if (client != null)
                {
                    context.Validated(client.RedirectUrl);
                }
            });
        }

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            return Task.Factory.StartNew(() =>
            {
                context.TryGetFormCredentials(out string clientId, out string clientSecret);

                var client = clientAppService.GetClientAppBytId(context.ClientId);

                if (client != null && clientSecret == client.Secret)
                {
                    context.Validated(clientId);
                }
            });
        }

        public override Task GrantClientCredentials(OAuthGrantClientCredentialsContext context)
        {
            return Task.Factory.StartNew(() =>
            {
                var client = clientAppService.GetClientAppBytId(context.ClientId);
                var oAuthIdentity = new ClaimsIdentity(context.Options.AuthenticationType);
                oAuthIdentity.AddClaim(new Claim(ClaimTypes.Name, client.Name));
                var ticket = new AuthenticationTicket(oAuthIdentity, new AuthenticationProperties());
                context.Validated(ticket);
            });
        }

        public override Task GrantAuthorizationCode(OAuthGrantAuthorizationCodeContext context)
        {
            return base.GrantAuthorizationCode(context);
        }

        public override Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            return base.GrantRefreshToken(context);
        }

        public override Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            return Task.Factory.StartNew(() =>
            {
                var username = context.UserName;
                var password = context.Password;
                var user = clientManager.Login(username, password);
                if (user != null)
                {
                    var claims = new List<Claim>()
                    {
                        new Claim(ClaimTypes.Name, $"{user.FName} {user.LName}"),
                        new Claim("UserID", user.ClientID.ToString())
                    };

                    ClaimsIdentity oAutIdentity = new ClaimsIdentity(claims, Startup.OAuthOptions.AuthenticationType);
                    context.Validated(new AuthenticationTicket(oAutIdentity, new AuthenticationProperties() { }));
                }
                else
                {
                    context.SetError("invalid_grant", "Error");
                }
            });
        }
    }

    public class OAuthAuthorizationCodeProvider : AuthenticationTokenProvider
    {
        private readonly ConcurrentDictionary<string, string> _authenticationCodes = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);

        public override Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            return Task.Factory.StartNew(() =>
            {
                context.SetToken(Guid.NewGuid().ToString("n") + Guid.NewGuid().ToString("n"));
                _authenticationCodes[context.Token] = context.SerializeTicket();
            });
        }

        public override Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            return Task.Factory.StartNew(() =>
            {
                if (_authenticationCodes.TryRemove(context.Token, out string value))
                {
                    context.DeserializeTicket(value);
                }
            });
        }
    }

    public class OAuthRefreshTokenProvider : AuthenticationTokenProvider
    {
        public override void Create(AuthenticationTokenCreateContext context) => context.SetToken(context.SerializeTicket());

        public override void Receive(AuthenticationTokenReceiveContext context) => context.DeserializeTicket(context.Token);
    }
}