/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Services;
using System.Web.Mvc;
using NLog;

namespace Thinktecture.IdentityServer.Protocols.WSFederation
{
    public class WSFederationResult : ContentResult
    {
        static Logger logger = LogManager.GetCurrentClassLogger();

        public WSFederationResult(SignInResponseMessage message, bool requireSsl)
        {
            if (requireSsl)
            {
                if (message.BaseUri.Scheme != Uri.UriSchemeHttps)
                {
                    logger.Error(Resources.WSFederation.WSFederationResult.ReturnUrlMustBeSslException);
                    throw new InvalidRequestException(Resources.WSFederation.WSFederationResult.ReturnUrlMustBeSslException);
                }
            }

            Content = message.WriteFormPost();
        }
    }
}