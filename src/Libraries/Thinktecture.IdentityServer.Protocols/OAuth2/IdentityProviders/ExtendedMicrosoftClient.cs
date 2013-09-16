using System;
using System.IO;
using System.Net;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DotNetOpenAuth.AspNet;
using DotNetOpenAuth.AspNet.Clients;
using Newtonsoft.Json.Linq;
using System.Collections.Specialized;
using System.Web;
using System.Security.Claims;
using System.Net.Http;
using Newtonsoft.Json;
using Thinktecture.IdentityModel;

namespace Thinktecture.IdentityServer.Protocols.OAuth2.IdentityProviders
{
    //Extention of MicrosoftClient to allow a custom scope.
    //TODO: Extend all identity providers to allow custom scope.
    public class ExtendedMicrosoftClient : MicrosoftClient
    {
        private const string AuthorizationEndpoint = "https://login.live.com/oauth20_authorize.srf";        
        /// <summary>
        /// The _app id.
        /// </summary>
        private readonly string appId;

        /// <summary>
        /// The _app secret.
        /// </summary>
        private readonly string appSecret;

        /// <summary>
        /// the scope for profile data
        /// </summary>
        private readonly string scope;

        /// <summary>
        /// Initializes a new instance of the <see cref="MicrosoftClient"/> class.
        /// </summary>
        /// <param name="appId">
        /// The app id.
        /// </param>
        /// <param name="appSecret">
        /// The app secret.
        /// </param>
        public ExtendedMicrosoftClient(string appId, string appSecret, string scope = null)
            : this("microsoft", appId, appSecret, scope)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="MicrosoftClient"/> class.
        /// </summary>
        /// <param name="providerName">The provider name.</param>
        /// <param name="appId">The app id.</param>
        /// <param name="appSecret">The app secret.</param>
        public ExtendedMicrosoftClient(string providerName, string appId, string appSecret, string scope)
            : base(providerName, appId, appSecret)
        {
            //Requires.NotNullOrEmpty(appId, "appId");
            //Requires.NotNullOrEmpty(appSecret, "appSecret");

            this.appId = appId;
            this.appSecret = appSecret;
            if (string.IsNullOrEmpty(scope))
            {
                this.scope = "wl.signin%20wl.basic";
            }
            else
            {
                this.scope = scope;
            }
        }


        protected override Uri GetServiceLoginUrl(Uri returnUrl)
        {
            var state = Base64Url.Encode(CryptoRandom.CreateRandomKey(10));
            var authorizationUrl = String.Format("{0}?scope={1}&response_type=code&redirect_uri={2}&client_id={3}",
                AuthorizationEndpoint,
                scope,
                HttpUtility.UrlEncode(returnUrl.AbsoluteUri),
                this.appId);

            return new Uri(authorizationUrl);
        }

        protected override IDictionary<string, string> GetUserData(string accessToken)
        {
            //MicrosoftClientUserData graph;
            var url = "https://apis.live.net/v5.0/me?access_token=" + accessToken;



            var client = new WebClient();
            var result = client.DownloadString(url);
            dynamic profile = JObject.Parse(result);

            var profileValues = new Dictionary<string, string>();
            profileValues.Add("email", profile.emails.account.Value);
            profileValues.Add("id", profile.id.Value);
            profileValues.Add("username", profile.emails.account.Value);
            return profileValues;
        }

        public override AuthenticationResult VerifyAuthentication(System.Web.HttpContextBase context, Uri returnPageUrl)
        {
            return base.VerifyAuthentication(context, returnPageUrl);
        }
    }
}


