﻿using LNF;
using LNF.Authorization.Credentials;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OnlineServices.Api;
using OnlineServices.Api.Authorization;
using System;

namespace Authentication.Tests
{
    [TestClass]
    public class ApiTests
    {
        [TestMethod]
        public void CanAuthorize()
        {
            var authSvc = new AuthorizationService(ApiClient.NewRestClient());
            var result = authSvc.Authorize(new PasswordCredentials("jgett", ServiceProvider.Current.DataAccess.UniversalPassword));
            Console.WriteLine(result.AccessToken);
            Assert.IsFalse(string.IsNullOrEmpty(result.AccessToken));
        }
    }
}
