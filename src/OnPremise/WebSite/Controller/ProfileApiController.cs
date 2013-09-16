using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Configuration;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.ServiceModel.Security.Tokens;
using System.Threading;
using System.Web;
using System.Web.Http;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.Web.Controllers
{
    public class ProfileApiController : ApiController
    {
        [Import]
        private IUserManagementRepository UserManagementRepository;

        [Import]
        private IRelyingPartyRepository RelyingPartyRepository;


        [Import]
        private IConfigurationRepository ConfigurationRepository { get; set; }

        public ProfileApiController(IUserManagementRepository userManagementRepository, IConfigurationRepository configurationRepository, IRelyingPartyRepository relyingPartyRepository)
        {
            UserManagementRepository = userManagementRepository;
            //ClientRepository = clientRepository;
            ConfigurationRepository = configurationRepository;
            RelyingPartyRepository = relyingPartyRepository;
        }
        public ProfileApiController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }


        // GET api/profileapi?accesstoken=
        public UserProfile Get(string accesstoken)
        {
            JwtSecurityToken jwToken = new JwtSecurityToken(accesstoken);
            var Issuer = ConfigurationRepository.Global.IssuerUri;

            if (jwToken.Issuer.ToLower().Equals(Issuer.ToLower()))
            {
                RelyingParty rp;
                if (RelyingPartyRepository.TryGet(jwToken.Audience, out rp))
                {                    
                    try
                    {
                        var claims = ValidateJwtToken(jwToken, rp);
                        return UserManagementRepository.GetByUsername(claims.Name);
                    }

                    catch (SecurityTokenValidationException ex)
                    {
                        throw new UnauthorizedAccessException();
                    }
                    catch (Exception e)
                    {
                        throw new UnauthorizedAccessException();
                    }
                }
                else
                {
                    throw new Exception("RP is false");
                }
            }
            else
            {
                throw new Exception("Issuer is false");
            }
        }

        private ClaimsIdentity ValidateJwtToken(JwtSecurityToken jwt, RelyingParty rp)
        {
            var handler = new JwtSecurityTokenHandler();

            var validationParameters = new TokenValidationParameters()
            {               
                //AudienceUriMode = AudienceUriMode.Never,
                SigningToken = new BinarySecretSecurityToken(rp.SymmetricSigningKey),
                ValidIssuer = ConfigurationRepository.Global.IssuerUri,
                AllowedAudience = jwt.Audience
            };

            var principal = handler.ValidateToken(jwt, validationParameters);
            return principal.Identities.First();
        }
    }

}
