/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

//using BrockAllen.OAuth2;
using Microsoft.Web.WebPages.OAuth;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel.Composition;
using System.IdentityModel.Configuration;
using System.IdentityModel.Selectors;
using System.IdentityModel.Services;
using System.IdentityModel.Services.Configuration;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.TokenService;
using DotNetOpenAuth.AspNet;
using DotNetOpenAuth.AspNet.Clients;
using WebMatrix.WebData;
using NLog;

namespace Thinktecture.IdentityServer.Protocols.WSFederation
{
    //TODO rebuild HRD to support HRD
    public class HrdController : AccountControllerBase
    {
        static Logger logger = LogManager.GetCurrentClassLogger();

        const string _cookieName = "hrdsignout";
        const string _cookieNameIdp = "hrdidp";
        const string _cookieNameRememberHrd = "hrdSelection";
        const string _cookieContext = "idsrvcontext";
        const string _cookieOAuthContext = "idsrvoauthcontext";

        [Import]
        public IConfigurationRepository ConfigurationRepository { get; set; }

        [Import]
        public IIdentityProviderRepository IdentityProviderRepository { get; set; }

        [Import]
        public IUserManagementRepository UserManagementRepository { get; set; }
        
        public HrdController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public HrdController(IConfigurationRepository configurationRepository, IIdentityProviderRepository identityProviderRepository, IUserManagementRepository userManagementRepository)
        {
            IdentityProviderRepository = identityProviderRepository;
            ConfigurationRepository = configurationRepository;
            UserManagementRepository = userManagementRepository;
        }

        #region Protocol Implementation
        [HttpGet]
        [ActionName("Issue")]
        public ActionResult ProcessRequest()
        {
            logger.Info("HRD endpoint called.");

            var message = WSFederationMessage.CreateFromUri(HttpContext.Request.Url);

            // sign in 
            var signinMessage = message as SignInRequestMessage;
            if (signinMessage != null)
            {
                return ProcessSignInRequest(signinMessage);
            }

            // sign out
            var signoutMessage = message as SignOutRequestMessage;
            if (signoutMessage != null)
            {
                return ProcessWSFedSignOutRequest(signoutMessage);
            }

            // sign out cleanup
            var cleanupMessage = message as SignOutCleanupRequestMessage;
            if (cleanupMessage != null)
            {
                return ProcessWSFedSignOutCleanupRequest(cleanupMessage);
            }

            return View("Error");
        }

        [HttpPost]
        [ActionName("Issue")]
        public ActionResult ProcessWSFedResponse()
        {
            var fam = new WSFederationAuthenticationModule();
            fam.FederationConfiguration = new FederationConfiguration();

            if (ConfigurationRepository.Keys.DecryptionCertificate != null)
            {
                var idConfig = new IdentityConfiguration();
                
                idConfig.ServiceTokenResolver = SecurityTokenResolver.CreateDefaultSecurityTokenResolver(
                     new ReadOnlyCollection<SecurityToken>(new SecurityToken[] { new X509SecurityToken(ConfigurationRepository.Keys.DecryptionCertificate) }), false);
                fam.FederationConfiguration.IdentityConfiguration = idConfig;
            }

            if (fam.CanReadSignInResponse(Request))
            {
                var token = fam.GetSecurityToken(Request);
                return ProcessWSFedSignInResponse(fam.GetSignInResponseMessage(Request), token);
            }

            return View("Error");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [ActionName("Select")]
        public ActionResult ProcessHRDSelection(string idp, string originalSigninUrl, bool rememberHRDSelection = false)
        {
            logger.Info("HRD selected: " + idp);

            var uri = new Uri(originalSigninUrl);
            var message = WSFederationMessage.CreateFromUri(uri);
            var signinMessage = message as SignInRequestMessage;

            var ip = GetVisibleIdentityProviders().Where(x => x.Name == idp).FirstOrDefault();
            if (ip == null || signinMessage == null) return View("Error");

            try
            {
                if (rememberHRDSelection)
                {
                    SetRememberHRDCookieValue(idp);
                }

                if (ip.Type == IdentityProviderTypes.WSStar)
                {
                    signinMessage.HomeRealm = ip.Name;
                    return RedirectToWSFedIdentityProvider(ip, signinMessage);
                }

                if (ip.Type == IdentityProviderTypes.OAuth2)
                {
                    return RedirectToOAuth2IdentityProvider(ip, signinMessage);
                }
                if (ip.Type == IdentityProviderTypes.OpenId)
                {
                    return RedirectToOpenIdIdentityProvider(ip, signinMessage);
                }
            }
            catch (Exception ex)
            {
                logger.Error(ex.ToString());
            }

            return View("Error");
        } 

        [AllowAnonymous]
        [ActionName("OAuthTokenCallback")]
        //TODO claims management. UserName doesn't have to be Email.
        //TODO add messages to language file system
        public ActionResult OAuthTokenCallback(string returnUrl)
        {
            var uri = new Uri(returnUrl);
            var redirectUri = Url.Action("OAuthTokenCallback", new { ReturnUrl = returnUrl });
            AuthenticationResult result = OAuthWebSecurity.VerifyAuthentication(redirectUri.ToLower());

            if (!result.IsSuccessful)
            {
                return RedirectToAction("ExternalLoginFailure");
            }
            //User Name is always email.
            var userName = OAuthWebSecurity.GetUserName(result.Provider, result.ProviderUserId);
            //var email = result.ExtraData.Select(d => d.Key.Contains("email"));
            if (!string.IsNullOrEmpty(userName))
            {
                return SignIn(
                    userName,
                    AuthenticationMethods.Unspecified,
                    uri.PathAndQuery,
                    false,
                    ConfigurationRepository.Global.SsoCookieLifetime);
            }

            if (User.Identity.IsAuthenticated)
            {
                // If the current user is logged in add the new account   
                if(UserManagementRepository.CreateOrUpdateOAuthAccount(result.Provider, result.ProviderUserId, User.Identity.Name))
                {
                    return RedirectToLocal(returnUrl);
                }
                else
                {
                    return RedirectToAction("Index", "Error", new { message = "An Identity provider of the type" + result.Provider + " is already added to this account" });
                }

            }
            else
            {
                // User is new, Create a new user and us there email as username
                if (UserManagementRepository.CreateOrUpdateOAuthAccount(result.Provider, result.ProviderUserId, result.UserName))
                {
                    return SignIn(
                        result.UserName,
                        AuthenticationMethods.HardwareToken,
                        uri.PathAndQuery,
                        false,
                        ConfigurationRepository.Global.SsoCookieLifetime);
                }
                else
                {
                    return RedirectToAction("Index", "Error", new { message = "An error occured while trying to create an account" });
                }
            }
        }


        #endregion

        #region Helper
        private ActionResult ProcessSignInRequest(SignInRequestMessage message)
        {
            if (!string.IsNullOrWhiteSpace(message.HomeRealm))
            {
                return RedirectToWSFedIdentityProvider(message);
            }
            else
            {
                var pastHRDSelection = GetRememberHRDCookieValue();
                if (String.IsNullOrWhiteSpace(pastHRDSelection))
                {
                    return ShowHomeRealmSelection(message);
                }
                else
                {
                    return ProcessHomeRealmFromCookieValue(message, pastHRDSelection);
                }
            }
        }

        [ChildActionOnly]
        public ActionResult GetIdentityProviders(string ReturnUrl)
        {
#if DEBUG
            UriBuilder b = new UriBuilder("https:", this.Request.Url.Host, 44300);

#else
            UriBuilder b = new UriBuilder("https:", this.Request.Url.Host);
#endif

            string wreply = b.ToString();
            string wtrealm = b.ToString();

            SignInRequestMessage message = new SignInRequestMessage(new Uri(wtrealm), wtrealm);

            if(string.IsNullOrEmpty(ReturnUrl))
            {
                ReturnUrl = "/account/myprofile";

            }
            message.Reply = b.ToString().TrimEnd('/') + ReturnUrl;
            return ShowHomeRealmSelection(message, "IdentityProviders");
        }

        private ActionResult ProcessWSFedSignOutRequest(SignOutRequestMessage message)
        {
            var idp = GetIdpCookie();
            if (string.IsNullOrWhiteSpace(idp))
            {
                return ShowSignOutPage(message.Reply);
            }

            var signOutMessage = new SignOutRequestMessage(new Uri(idp));
            if (!string.IsNullOrWhiteSpace(message.Reply))
            {
                signOutMessage.Reply = message.Reply;
            }

            return Redirect(signOutMessage.WriteQueryString());
        }

        private ActionResult ProcessWSFedSignOutCleanupRequest(SignOutCleanupRequestMessage message)
        {
            return ShowSignOutPage(message.Reply);
        }

        private ActionResult ShowSignOutPage(string returnUrl)
        {
            // check for return url
            if (!string.IsNullOrWhiteSpace(returnUrl))
            {
                ViewBag.ReturnUrl = returnUrl;
            }

            // check for existing sign in sessions
            var mgr = new SignInSessionsManager(HttpContext, _cookieName);
            var realms = mgr.GetEndpoints();
            mgr.ClearEndpoints();

            return View("Signout", realms);
        }

        private ActionResult RedirectToWSFedIdentityProvider(SignInRequestMessage request)
        {
            IdentityProvider idp = null;
            if (IdentityProviderRepository.TryGet(request.HomeRealm, out idp) && idp.Enabled)
            {
                return RedirectToWSFedIdentityProvider(idp, request);
            }

            return View("Error");
        }

        private ActionResult RedirectToWSFedIdentityProvider(IdentityProvider identityProvider, SignInRequestMessage request)
        {
            var message = new SignInRequestMessage(new Uri(identityProvider.WSFederationEndpoint), ConfigurationRepository.Global.IssuerUri);
            SetContextCookie(request.Context, request.Realm, identityProvider.WSFederationEndpoint);

            return new RedirectResult(message.WriteQueryString());
        }

        private ActionResult RedirectToOAuth2IdentityProvider(IdentityProvider ip, SignInRequestMessage request)
        {
            return new ExternalLoginResult(ip.OAuth2ProviderType.ToString(), ("~/" + Thinktecture.IdentityServer.Endpoints.Paths.OAuth2Callback + "?ReturnUrl=" + HttpUtility.UrlEncode(request.Reply)).ToLower());
        }

        private ActionResult RedirectToOpenIdIdentityProvider(IdentityProvider ip, SignInRequestMessage request)
        {
            return new ExternalLoginResult(ip.OpenIdProviderType.ToString(), ("~/" + Thinktecture.IdentityServer.Endpoints.Paths.OAuth2Callback + "?ReturnUrl=" + HttpUtility.UrlEncode(request.Reply)).ToLower());
        }

        internal class ExternalLoginResult : ActionResult
        {
            public ExternalLoginResult(string provider, string returnUrl)
            {
                Provider = provider;
                ReturnUrl = returnUrl;
            }

            public string Provider { get; private set; }
            public string ReturnUrl { get; private set; }

            public override void ExecuteResult(ControllerContext context)
            {
                OAuthWebSecurity.RequestAuthentication(Provider, ReturnUrl);
            }
        }

        private ActionResult ProcessWSFedSignInResponse(SignInResponseMessage responseMessage, SecurityToken token)
        {
            var principal = ValidateToken(token);
            var issuerName = principal.Claims.First().Issuer;

            principal.Identities.First().AddClaim(
                new Claim(Constants.Claims.IdentityProvider, issuerName, ClaimValueTypes.String, Constants.InternalIssuer));

            var context = GetContextCookie();
            var message = new SignInRequestMessage(new Uri("http://foo"), context.Realm);
            message.Context = context.Wctx;

            // issue token and create ws-fed response
            var wsFedResponse = FederatedPassiveSecurityTokenServiceOperations.ProcessSignInRequest(
                message,
                principal,
                TokenServiceConfiguration.Current.CreateSecurityTokenService());

            // set cookie for single-sign-out
            new SignInSessionsManager(HttpContext, _cookieName, ConfigurationRepository.Global.MaximumTokenLifetime)
                .AddEndpoint(wsFedResponse.BaseUri.AbsoluteUri);

            // set cookie for idp signout
            SetIdPCookie(context.WsFedEndpoint);

            return new WSFederationResult(wsFedResponse, requireSsl: ConfigurationRepository.WSFederation.RequireSslForReplyTo);
        }
        
        IEnumerable<IdentityProvider> GetEnabledWSIdentityProviders()
        {
            return IdentityProviderRepository.GetAll().Where(
                x => x.Enabled && x.Type == IdentityProviderTypes.WSStar);
        }

        IEnumerable<IdentityProvider> GetVisibleIdentityProviders()
        {
            return IdentityProviderRepository.GetAll().Where(
                x => x.Enabled && x.ShowInHrdSelection);
        }

        private ClaimsPrincipal ValidateToken(SecurityToken token)
        {
            var config = new SecurityTokenHandlerConfiguration();
            config.AudienceRestriction.AudienceMode = AudienceUriMode.Always;
            config.AudienceRestriction.AllowedAudienceUris.Add(new Uri(ConfigurationRepository.Global.IssuerUri));
            
            var registry = new IdentityProviderIssuerNameRegistry(GetEnabledWSIdentityProviders());
            config.IssuerNameRegistry = registry;
            config.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;
            config.CertificateValidator = X509CertificateValidator.None;

            var handler = SecurityTokenHandlerCollection.CreateDefaultSecurityTokenHandlerCollection(config);
            var identity = handler.ValidateToken(token).First();

            return new ClaimsPrincipal(identity);
        }

        private ActionResult ShowHomeRealmSelection(SignInRequestMessage message, string patialView = "")
        {
            var idps = GetVisibleIdentityProviders();

            logger.Info("HRD selection screen displayed.");
            var vm = new HrdViewModel(message, idps);
            if (string.IsNullOrEmpty(patialView))
            {
                return View("HRD", vm);
            }
            else
            {
                return PartialView(patialView, vm);
            }
        }
        #endregion


        #region Cookies
        private void SetIdPCookie(string url)
        {
            var cookie = new HttpCookie(_cookieNameIdp, url)
            {
                Secure = true,
                HttpOnly = true,
                Path = HttpRuntime.AppDomainAppVirtualPath
            };

            Response.Cookies.Add(cookie);
        }

        private string GetIdpCookie()
        {
            var cookie = Request.Cookies[_cookieNameIdp];
            if (cookie == null)
            {
                return null;
            }

            var idp = cookie.Value;

            cookie.Value = "";
            cookie.Expires = new DateTime(2000, 1, 1);
            cookie.Path = HttpRuntime.AppDomainAppVirtualPath;
            Response.SetCookie(cookie);

            return idp;
        }

        private void SetContextCookie(string wctx, string realm, string wsfedEndpoint)
        {
            var j = JObject.FromObject(new Context { Wctx = wctx, Realm = realm, WsFedEndpoint = wsfedEndpoint });

            var cookie = new HttpCookie(_cookieContext, j.ToString())
            {
                Secure = true,
                HttpOnly = true,
                Path = HttpRuntime.AppDomainAppVirtualPath
            };

            Response.Cookies.Add(cookie);
        }

        private Context GetContextCookie()
        {
            var cookie = Request.Cookies[_cookieContext];
            if (cookie == null)
            {
                throw new InvalidOperationException("cookie");
            }

            var json = JObject.Parse(HttpUtility.UrlDecode(cookie.Value));

            cookie.Value = "";
            cookie.Expires = new DateTime(2000, 1, 1);
            cookie.Path = HttpRuntime.AppDomainAppVirtualPath;
            Response.SetCookie(cookie);

            return json.ToObject<Context>();
        }


        private void SetRememberHRDCookieValue(string realm)
        {
            var cookie = new HttpCookie(_cookieNameRememberHrd);
            if (String.IsNullOrWhiteSpace(realm))
            {
                realm = ".";
                cookie.Expires = DateTime.UtcNow.AddYears(-1);
            }
            else
            {
                cookie.Expires = DateTime.Now.AddMonths(1);
            }
            cookie.Value = realm;
            cookie.HttpOnly = true;
            cookie.Secure = true;
            cookie.Path = Request.ApplicationPath;
            Response.Cookies.Add(cookie);
        }

        private string GetRememberHRDCookieValue()
        {
            if (Request.Cookies.AllKeys.Contains(_cookieNameRememberHrd))
            {
                var cookie = Request.Cookies[_cookieNameRememberHrd];
                var realm = cookie.Value;
                var idps = GetVisibleIdentityProviders().Where(x => x.Name == realm);
                var idp = idps.SingleOrDefault();
                if (idp == null)
                {
                    logger.Info("Past HRD selection from cookie not found in current HRD list. Past value was: " + realm);
                    SetRememberHRDCookieValue(null);
                }

                return realm;
            }

            return null;
        }

        private ActionResult ProcessHomeRealmFromCookieValue(SignInRequestMessage message, string pastHRDSelection)
        {
            message.HomeRealm = pastHRDSelection;
            return ProcessSignInRequest(message);
        }

        internal class Context
        {
            public string Wctx { get; set; }
            public string Realm { get; set; }
            public string WsFedEndpoint { get; set; }
            public string ReturnUrl { get; set; }
        }

        #endregion
    }
}
