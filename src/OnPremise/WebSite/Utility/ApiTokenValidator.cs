//using System;
//using System.Collections.Generic;
//using System.Configuration;
//using System.IdentityModel.Tokens;
//using System.Linq;
//using System.Net;
//using System.Net.Http;
//using System.Security.Claims;
//using System.ServiceModel.Security.Tokens;
//using System.Text;
//using System.Threading;
//using System.Threading.Tasks;
//using System.Web;

//namespace Thinktecture.IdentityServer.Web.Utility
//{
//    public class ApiTokenValidator
//    {
//        private bool TryGetToken(HttpRequestMessage request, out string token)
//        {
//            IEnumerable<string> headers;

//            token = null;

//            if (!request.Headers.TryGetValues("Authorization", out headers) || headers.Count() > 1)
//            {
//                return false;
//            }

//            var bearer = headers.ElementAt(0);

//            token = bearer.StartsWith("Bearer ") ? bearer.Substring(7) : bearer;

//            return true;
//        }

//        protected static Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
//        {
//            HttpStatusCode status;
//            string token;

//            if (request.Method == HttpMethod.Options)
//            {
//                //return base.SendAsync(request, cancellationToken);
//            }

//           // if (!TryGetToken(request, out token))
//          //  {
//         //       status = HttpStatusCode.Unauthorized;

//        //        return Task<HttpResponseMessage>.Factory.StartNew(() => new HttpResponseMessage(status));
//        //    }

//            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();

//            try
//            {
//                ClaimsPrincipal principal = handler.ValidateToken(token, new TokenValidationParameters()
//                {
//                    ValidIssuer = ConfigurationManager.AppSettings["oauth.issuer"],
//                    AllowedAudience = ConfigurationManager.AppSettings["oauth.scope"],
//                    SigningToken = new BinarySecretSecurityToken(Convert.FromBase64String(ConfigurationManager.AppSettings["oauth.signingkey"]))
//                });

//                Thread.CurrentPrincipal = principal;
//                HttpContext.Current.User = principal;

//                //return base.SendAsync(request, cancellationToken);
//            }
//            catch (SecurityTokenValidationException ex)
//            {
//                status = HttpStatusCode.Unauthorized;
//            }
//            catch (Exception)
//            {
//                status = HttpStatusCode.InternalServerError;
//            }

//            return Task<HttpResponseMessage>.Factory.StartNew(() => new HttpResponseMessage(status));
//        }
//    }
//}