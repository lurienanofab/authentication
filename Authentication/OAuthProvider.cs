using Authentication.Models;
using LNF;
using LNF.CommonTools;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Authentication
{
    public class OAuthProvider : OAuthAuthorizationServerProvider
    {
        //private readonly UserService userService;
        protected IProvider Provider { get; }
        private readonly ClientAppRepository clientAppRepo;

        public OAuthProvider(IProvider provider)
        {
            //userService = new UserService();
            Provider = provider;
            clientAppRepo = new ClientAppRepository();
        }

        public override Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            var client = clientAppRepo.GetClientAppBytId(context.ClientId);

            if (client != null)
            {
                if (client.Redirects.Contains(context.RedirectUri))
                {
                    _ = context.Validated();
                }
            }

            return Task.FromResult<object>(null);
        }

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            // Called by the /token request, should return a token if the clientId and clientSecret are correct

            if (!context.TryGetBasicCredentials(out string clientId, out string clientSecret))
                context.TryGetFormCredentials(out clientId, out clientSecret);

            var client = clientAppRepo.GetClientAppBytId(context.ClientId);

            if (client != null && clientSecret == client.Secret)
            {
                context.Validated(clientId);
            }

            return Task.FromResult<object>(null);
        }

        public override Task GrantClientCredentials(OAuthGrantClientCredentialsContext context)
        {
            var client = clientAppRepo.GetClientAppBytId(context.ClientId);
            var oAuthIdentity = new ClaimsIdentity(context.Options.AuthenticationType);
            oAuthIdentity.AddClaim(new Claim(ClaimTypes.Name, client.Name));
            var ticket = new AuthenticationTicket(oAuthIdentity, new AuthenticationProperties());
            context.Validated(ticket);

            return Task.FromResult<object>(null);
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
            var username = context.UserName;
            var password = context.Password;

            var user = Provider.Data.Client.AuthUtility().Login(username, password);

            if (user != null)
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, $"{user.FName} {user.LName}"),
                    new Claim("UserID", user.ClientID.ToString())
                };

                ClaimsIdentity oAutIdentity = new ClaimsIdentity(claims, Startup.GetServerOptions(Provider).AuthenticationType);
                context.Validated(new AuthenticationTicket(oAutIdentity, new AuthenticationProperties() { }));
            }
            else
            {
                context.SetError("invalid_grant", "Error");
            }

            return Task.FromResult<object>(null);
        }
    }

    public class OAuthAuthorizationCodeProvider : AuthenticationTokenProvider
    {
        private readonly ConcurrentDictionary<string, string> _authenticationCodes = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);

        public override Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            string token = Guid.NewGuid().ToString("n") + Guid.NewGuid().ToString("n");
            context.SetToken(token);

            string ticket = context.SerializeTicket();
            _authenticationCodes[context.Token] = ticket;

            return Task.FromResult<object>(null);
        }

        public override Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            if (_authenticationCodes.TryRemove(context.Token, out string value))
            {
                context.DeserializeTicket(value);
            }

            return Task.FromResult<object>(null);
        }
    }

    public class OAuthRefreshTokenProvider : AuthenticationTokenProvider
    {
        public override void Create(AuthenticationTokenCreateContext context) => context.SetToken(context.SerializeTicket());

        public override void Receive(AuthenticationTokenReceiveContext context) => context.DeserializeTicket(context.Token);
    }
}