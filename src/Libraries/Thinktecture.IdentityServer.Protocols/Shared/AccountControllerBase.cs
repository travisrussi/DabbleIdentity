/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.IdentityModel.Services;
using System.Security.Claims;
using System.Web.Mvc;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.TokenService;

namespace Thinktecture.IdentityServer.Protocols
{
    public class AccountControllerBase : Controller
    {
        [Import]
        public IUserRepository UserRepository { get; set; }

        [Import]
        public IConfigurationRepository ConfigurationRepository { get; set; }

        public AccountControllerBase()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public AccountControllerBase(IUserRepository userRepository, IConfigurationRepository configurationRepository)
        {
            UserRepository = userRepository;
            ConfigurationRepository = configurationRepository;
        }

        public ActionResult SignOut()
        {
            if (Request.IsAuthenticated)
            {
                FederatedAuthentication.SessionAuthenticationModule.DeleteSessionTokenCookie();
            }

            return RedirectToAction("Signin", "Account");
        }

        #region Private
        protected virtual ActionResult SignIn(string userName, string authenticationMethod, string returnUrl, bool isPersistent, int ttl, IEnumerable<Claim> additionalClaims = null)
        {
            new AuthenticationHelper().SetSessionToken(
                userName,
                authenticationMethod,
                isPersistent,
                ttl,
                additionalClaims);

            if (!string.IsNullOrWhiteSpace(returnUrl))
            {
                return RedirectToLocal(returnUrl);
            }
            ViewBag.IsSignedIn = true;
            return RedirectToAction("myprofile", "account");
        }

        public ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Signin", "Account");
            }
        }
        #endregion
    }
}