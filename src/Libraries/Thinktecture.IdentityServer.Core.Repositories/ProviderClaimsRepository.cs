/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Web.Profile;
using System.Web.Security;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.TokenService;

namespace Thinktecture.IdentityServer.Repositories
{
    public class ProviderClaimsRepository : IClaimsRepository
    {
        private const string ProfileClaimPrefix = "http://identityserver.thinktecture.com/claims/profileclaims/";

        public virtual IEnumerable<Claim> GetClaims(ClaimsPrincipal principal, RequestDetails requestDetails)
        {
            var userName = principal.Identity.Name;
            var claims = new List<Claim>(from c in principal.Claims select c);

            // email address
            string email = userName;
            if (!String.IsNullOrEmpty(email))
            {
                    claims.Add(new Claim(ClaimTypes.Email, email));                
            }

            // roles
            GetRolesForToken(userName).ToList().ForEach(role => claims.Add(new Claim(ClaimTypes.Role, role)));

            // profile claims
            claims.AddRange(GetProfileClaims(userName));
            return claims;
        }

        protected virtual IEnumerable<Claim> GetProfileClaims(string userName)
        {
            var claims = new List<Claim>();

            if (ProfileManager.Enabled)
            {
                IUserManagementRepository user = new ProviderUserManagementRepository();
                UserProfile profile = user.GetByUsername(userName);
                //= .Create(userName, true) as UserProfile;
                //var profile = ProfileBase.Create(userName, true);
                if (profile != null)
                {
                    foreach (var prop in profile.GetType().GetProperties())
                    {
                        var exist = prop.GetCustomAttribute<ClaimAttribute>();
                        if (exist != null)
                        {
                            object value = prop.GetValue(profile);
                            if (value != null)
                            {
                                claims.Add(new Claim(GetProfileClaimType(prop.Name.ToLowerInvariant()), value.ToString()));
                            }
                        }
                    }
                }
            }

            return claims;
        }

        protected virtual string GetProfileClaimType(string propertyName)
        {
            if (StandardClaimTypes.Mappings.ContainsKey(propertyName))
            {
                return StandardClaimTypes.Mappings[propertyName];
            }
            else
            {
                return string.Format("{0}{1}", ProfileClaimPrefix, propertyName);
            }
        }


        public virtual IEnumerable<string> GetSupportedClaimTypes()
        {
            var claimTypes = new List<string>
            {
                ClaimTypes.Name,
                ClaimTypes.Email,
                ClaimTypes.Role
            };

            if (ProfileManager.Enabled)
            {
                foreach (PropertyInfo prop in typeof(UserProfile).GetProperties())
                {
                    var exist = prop.GetCustomAttribute<ClaimAttribute>();
                    if (exist != null) 
                    {
                        claimTypes.Add(GetProfileClaimType(prop.Name.ToLowerInvariant()));
                    }
                }
            }

            return claimTypes;
        }

        protected virtual IEnumerable<string> GetRolesForToken(string userName)
        {
            var returnedRoles = new List<string>();

            if (Roles.Enabled)
            {
                var roles = Roles.GetRolesForUser(userName);
                returnedRoles = roles.Where(role => !(role.StartsWith(Constants.Roles.InternalRolesPrefix))).ToList();
            }

            return returnedRoles;
        }
    }
}