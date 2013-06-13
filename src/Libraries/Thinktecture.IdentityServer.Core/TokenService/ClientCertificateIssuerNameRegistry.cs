/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System;
using System.IdentityModel.Tokens;
using NLog;

namespace Thinktecture.IdentityServer.TokenService
{
    class ClientCertificateIssuerNameRegistry : IssuerNameRegistry
    {
        static Logger logger = LogManager.GetCurrentClassLogger();

        public override string GetIssuerName(SecurityToken securityToken)
        {
            if (securityToken == null)
            {
                logger.Error("ClientCertificateIssuerNameRegistry: securityToken is null");
                throw new ArgumentNullException("securityToken");
            }

            X509SecurityToken token = securityToken as X509SecurityToken;
            if (token != null)
            {
                logger.Info("ClientCertificateIssuerNameRegistry: X509 SubjectName: " + token.Certificate.SubjectName.Name);
                logger.Info("ClientCertificateIssuerNameRegistry: X509 Thumbprint : " + token.Certificate.Thumbprint);
                return token.Certificate.Thumbprint;
            }

            return null;
        }
    }
}
