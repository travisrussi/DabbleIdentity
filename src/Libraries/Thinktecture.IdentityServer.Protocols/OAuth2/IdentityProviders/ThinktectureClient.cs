using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Web;
using DotNetOpenAuth.Messaging;
using Validation;
using DotNetOpenAuth.AspNet.Clients;
using System.IO;
using System.Runtime.Serialization.Json;
using System.Text;
using Newtonsoft.Json;
using System.Globalization;
using System.Net.Http.Headers;
using System.Dynamic;

namespace Thinktecture.IdentityServer.Protocols.OAuth2.IdentityProviders
{
    /// <summary>
    /// The amazon client.
    /// </summary>
    public sealed class ThinktectureClient : OAuth2Client
    {
        #region Constants and Fields

        /// <summary>
        /// The authorization endpoint.
        /// </summary>
        private readonly string AuthorizationEndpoint;

        /// <summary>
        /// The token endpoint.
        /// </summary>
        private readonly string TokenEndpoint;

        /// <summary>
        /// The _app id.
        /// </summary>
        private readonly string clientId;

        /// <summary>
        /// The _app secret.
        /// </summary>
        private readonly string clientSecret;

        /// <summary>
        /// Thinktecture uses the realm to find the right relying party
        /// </summary>
        private readonly string realm;

        private readonly string idpDomain;

        #endregion

        #region Constructors and Destructors

        /// <summary>
        /// Initializes a new instance of the <see cref="FacebookClient"/> class.
        /// </summary>
        /// <param name="clientId">
        /// The app id.
        /// </param>
        /// <param name="clientSecret">
        /// The app secret.
        /// </param>
        /// <param name="scope">
        /// The scope of authorization to request when authenticating with Facebook. The default is "email".
        /// </param>
        public ThinktectureClient(string clientId, string clientSecret, string realm, string idpDomain)
            : base("Thinktecture")
        {
            Requires.NotNullOrEmpty(clientId, "clientId");
            Requires.NotNullOrEmpty(clientSecret, "clientSecret");
            Requires.NotNullOrEmpty(realm, "realm");
            Requires.NotNullOrEmpty(idpDomain, "idpDomain");

            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.realm = realm;
            this.idpDomain = idpDomain;

            AuthorizationEndpoint = "https://" + idpDomain + "/issue/oauth2/authorize";
            TokenEndpoint = "https://" + idpDomain + "/issue/oauth2/token";

        }

        #endregion

        #region Methods

        /// <summary>
        /// The get service login url.
        /// </summary>
        /// <param name="returnUrl">
        /// The return url.
        /// </param>
        /// <returns>An absolute URI.</returns>
        protected override Uri GetServiceLoginUrl(Uri returnUrl)
        {
            var test = HttpUtility.ParseQueryString(returnUrl.Query);
            

            var builder = new UriBuilder(AuthorizationEndpoint);
            builder.AppendQueryArgument("client_id", this.clientId);
            builder.AppendQueryArgument("redirect_uri", returnUrl.GetLeftPart(UriPartial.Path));
            builder.AppendQueryArgument("state", returnUrl.Query);
            // builder.AppendQueryArgument("redirect_uri", returnUrl.ToString());
            builder.AppendQueryArgument("response_type", "code");
            builder.AppendQueryArgument("scope", this.realm);

            return builder.Uri;
        }

        /// <summary>
        /// The get user data.
        /// </summary>
        /// <param name="accessToken">
        /// The access token.
        /// </param>
        /// <returns>A dictionary of profile data.</returns>
        protected override IDictionary<string, string> GetUserData(string accessToken)
        // protected override NameValueCollection GetUserData(string accessToken)
        {
            // dynamic userProfile;
            //var request = WebRequest.Create("https://bccidp.macaw.nl/user/profile?access_token=" + HttpUtility.UrlEncode(accessToken));
            //request.Headers.Add(HttpRequestHeader.Authorization, string.Format(CultureInfo.InvariantCulture, "Bearer {0}", accessToken));
            //request.PreAuthenticate = true;

            //using (var response = request.GetResponse())
            //{
            //    using (var responseStream = response.GetResponseStream())
            //    {
            //        using (StreamReader reader = new StreamReader(responseStream))
            //        {
            //            string responseData = reader.ReadToEnd();
            //            userProfile = JsonConvert.DeserializeObject<dynamic>(responseData);
            //        }
            //    }
            //}

            // this dictionary must contains 
            var userData = new Dictionary<string, string>();
            // var userData = new NameValueCollection();
            userData.Add("id", "1");
            //if (!string.IsNullOrEmpty(userProfile.PrimaryEmail)) userData.Add("email", userProfile.PrimaryEmail);
            //if (!string.IsNullOrEmpty(userProfile.Name)) userData.Add("name", userProfile.Name);
            //if (!string.IsNullOrEmpty(userProfile.PostalCode)) userData.Add("postal_code", userProfile.PostalCode);
            return userData;
        }


        /// <summary>
        /// Obtains an access token given an authorization code and callback URL.
        /// </summary>
        /// <param name="returnUrl">
        /// The return url.
        /// </param>
        /// <param name="authorizationCode">
        /// The authorization code.
        /// </param>
        /// <returns>
        /// The access token.
        /// </returns>
        protected override string QueryAccessToken(Uri returnUrl, string authorizationCode)
        {
            var sb = new StringBuilder();
            sb.Append("grant_type=authorization_code");
            sb.Append("&code=").Append(HttpUtility.UrlEncode(authorizationCode));
            // we need to circumvert DotNetOpenAuth adding its stuff to the returnUrl to the Redirect Uri... Amazon will reject it
            // sb.Append("&redirect_uri=").Append(HttpUtility.UrlEncode(returnUrl.GetLeftPart(UriPartial.Path)));
            // sb.Append("&client_id=").Append(HttpUtility.UrlEncode(this.clientId));
            // sb.Append("&client_secret=").Append(HttpUtility.UrlEncode(this.clientSecret));


            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(TokenEndpoint);
            request.Method = "POST";
            request.Headers["Authorization"] = new BasicAuthenticationHeaderValue(this.clientId, this.clientSecret).ToString();
            request.ContentType = "application/x-www-form-urlencoded";
            byte[] bytes = Encoding.UTF8.GetBytes(sb.ToString());
            request.ContentLength = bytes.Length;

            using (Stream requestStream = request.GetRequestStream())
            {
                requestStream.Write(bytes, 0, bytes.Length);

                using (WebResponse response = request.GetResponse())
                {
                    using (Stream stream = response.GetResponseStream())
                    {
                        var memstream = new MemoryStream();
                        //TODO remove readasstring
                        dynamic result = JsonConvert.DeserializeObject<dynamic>(stream.ReadAsString());
                        return result.access_token;
                    }
                }
            }
        }


        public override void RequestAuthentication(HttpContextBase context, Uri returnUrl)
        {
            base.RequestAuthentication(context, returnUrl);
        }

        public override DotNetOpenAuth.AspNet.AuthenticationResult VerifyAuthentication(HttpContextBase context, Uri returnPageUrl)
        {
            return base.VerifyAuthentication(context, returnPageUrl);
        }



        /// <summary>
        /// Converts any % encoded values in the URL to uppercase.
        /// </summary>
        /// <param name="url">The URL string to normalize</param>
        /// <returns>The normalized url</returns>
        /// <example>NormalizeHexEncoding("Login.aspx?ReturnUrl=%2fAccount%2fManage.aspx") returns "Login.aspx?ReturnUrl=%2FAccount%2FManage.aspx"</example>
        /// <remarks>
        /// There is an issue in Facebook whereby it will rejects the redirect_uri value if
        /// the url contains lowercase % encoded values.
        /// </remarks>
        private static string NormalizeHexEncoding(string url)
        {
            var chars = url.ToCharArray();
            for (int i = 0; i < chars.Length - 2; i++)
            {
                if (chars[i] == '%')
                {
                    chars[i + 1] = char.ToUpperInvariant(chars[i + 1]);
                    chars[i + 2] = char.ToUpperInvariant(chars[i + 2]);
                    i += 2;
                }
            }
            return new string(chars);
        }

        #endregion
    }

    public class BasicAuthenticationHeaderValue : AuthenticationHeaderValue
    {
        public BasicAuthenticationHeaderValue(string userName, string password)
            : base("Basic", EncodeCredential(userName, password))
        { }

        private static string EncodeCredential(string userName, string password)
        {
            Encoding encoding = Encoding.GetEncoding("iso-8859-1");
            string credential = String.Format("{0}:{1}", userName, password);

            return Convert.ToBase64String(encoding.GetBytes(credential));
        }
    }
}
