using LNF;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OnlineServices.Api;
using OnlineServices.Api.Authorization.Credentials;
using System;

namespace Authentication.Tests
{
    [TestClass]
    public class ApiTests
    {
        [TestMethod]
        public void CanAuthorize()
        {
            using (var authClient = new AuthorizationClient())
            {
                var result = authClient.Authorize(new PasswordCredentials("jgett", ServiceProvider.Current.DataAccess.UniversalPassword)).Result;
                Console.WriteLine(result.AccessToken);
                Assert.IsFalse(string.IsNullOrEmpty(result.AccessToken));
            }
        }
    }
}
