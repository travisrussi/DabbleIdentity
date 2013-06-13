using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.Web.WebPages.OAuth;
using DotNetOpenAuth.AspNet.Clients;
using System.ComponentModel.Composition;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.Protocols.OAuth2;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Protocols.OAuth2.IdentityProviders;


namespace Thinktecture.IdentityServer.Web.Utility
{
    public class AuthConfig
    {
        [Import]
        public IIdentityProviderRepository IdentityProviderRepository { get; set; }

        public void RegisterAllIdentityProviders()
        {
            Container.Current.SatisfyImportsOnce(this);

            var oauth2identityProviders = GetEnabledOauth2IdentityProviders();

            foreach (var identityProvider in oauth2identityProviders)
            {
                RegisterOauth2IdentityProvider(identityProvider);
            }

            var openIdidentityProviders = GetEnabledOpenIdIdentityProviders();

            foreach (var identityProvider in openIdidentityProviders)
            {
                RegisterOpenIdIdentityProvider(identityProvider);
            }
        }


        public void RemoveIdentityProvider(IdentityProvider identityProvider)
        {
            //OAuthWebSecurity.TryGetOAuthClientData(
            //foreach (var registeredIdentityProvider in OAuthWebSecurity.TryGetOAuthClientData.RegisteredClientData)
            //{
            //    if (registeredIdentityProvider.DisplayName == identityProvider.ProviderType.ToString())
            //    {
            //        registeredIdentityProvider.AuthenticationClient.
            //    }

            //}

        }

        public void RegisterOpenIdIdentityProvider(IdentityProvider identityProvider)
        {
            AuthenticationClientData client;
            switch (identityProvider.OpenIdProviderType)
            {                
                case OpenIdProviderTypes.Google:
                    if (!OAuthWebSecurity.TryGetOAuthClientData(identityProvider.OpenIdProviderType.ToString(), out client))
                    {
                        OAuthWebSecurity.RegisterGoogleClient(identityProvider.OAuth2ProviderType.ToString());
                    }
                    break;
            }
        }

        public void RegisterOauth2IdentityProvider(IdentityProvider identityProvider)
        {
            AuthenticationClientData client;
            switch (identityProvider.OAuth2ProviderType)
            {
                case OAuth2ProviderTypes.Facebook:
                    if (!OAuthWebSecurity.TryGetOAuthClientData(identityProvider.OAuth2ProviderType.ToString(), out client))
                    {
                        OAuthWebSecurity.RegisterFacebookClient(identityProvider.ClientID, identityProvider.ClientSecret, identityProvider.OAuth2ProviderType.ToString());
                    }
                    break;
                case OAuth2ProviderTypes.Microsoft:
                    if (!OAuthWebSecurity.TryGetOAuthClientData(identityProvider.OAuth2ProviderType.ToString(), out client))
                    {
                        var newClient = new ExtendedMicrosoftClient(identityProvider.ClientID, identityProvider.ClientSecret, "wl.signin%20wl.emails");
                        OAuthWebSecurity.RegisterClient(newClient, identityProvider.OAuth2ProviderType.ToString(), null);
                        //OAuthWebSecurity.RegisterMicrosoftClient(identityProvider.ClientID, identityProvider.ClientSecret, identityProvider.ProviderType.ToString());
                    }
                    break;
                case OAuth2ProviderTypes.LinkedIn:
                    if (!OAuthWebSecurity.TryGetOAuthClientData(identityProvider.OAuth2ProviderType.ToString(), out client))
                    {
                        OAuthWebSecurity.RegisterLinkedInClient(identityProvider.ClientID, identityProvider.ClientSecret, identityProvider.OAuth2ProviderType.ToString());
                    }
                    break;
                case OAuth2ProviderTypes.Twitter:
                    if (!OAuthWebSecurity.TryGetOAuthClientData(identityProvider.OAuth2ProviderType.ToString(), out client))
                    {
                        OAuthWebSecurity.RegisterTwitterClient(identityProvider.ClientID, identityProvider.ClientSecret, identityProvider.OAuth2ProviderType.ToString());
                    }
                    break;
                case OAuth2ProviderTypes.Yahoo:
                    if (!OAuthWebSecurity.TryGetOAuthClientData(identityProvider.OAuth2ProviderType.ToString(), out client))
                    {
                        OAuthWebSecurity.RegisterYahooClient(identityProvider.OAuth2ProviderType.ToString());
                    }
                    break;
            }
        }

        private IEnumerable<IdentityProvider> GetEnabledOauth2IdentityProviders()
        {
            return IdentityProviderRepository.GetAll().Where(
                x => x.Enabled && x.Type == IdentityProviderTypes.OAuth2);
        }

        private IEnumerable<IdentityProvider> GetEnabledOpenIdIdentityProviders()
        {
            return IdentityProviderRepository.GetAll().Where(
                x => x.Enabled && x.Type == IdentityProviderTypes.OpenId);
        }
    }
}