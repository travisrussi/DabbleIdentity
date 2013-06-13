/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using NLog;
using System;
using System.ComponentModel.Composition;
using System.IdentityModel.Protocols.WSTrust;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Text;
using Thinktecture.IdentityModel.Constants;
using Thinktecture.IdentityModel.Extensions;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.TokenService
{
    /// <summary>
    /// This class analyzes the token request so the STS can inspect the information later
    /// </summary>
    public class Request
    {
        static Logger logger = LogManager.GetCurrentClassLogger();
        IConfigurationRepository _configuration;
        RequestDetails _details;

        [Import]
        public IRelyingPartyRepository RelyingPartyRepository { get; set; }

        [Import]
        public IDelegationRepository DelegationRepository { get; set; }

        public Request(IConfigurationRepository configuration)
        {
            _configuration = configuration;
            Container.Current.SatisfyImportsOnce(this);
        }

        public Request(IConfigurationRepository configuration, IRelyingPartyRepository relyingPartyRepository, IDelegationRepository delegationRepository)
        {
            _configuration = configuration;
            RelyingPartyRepository = relyingPartyRepository;
            DelegationRepository = delegationRepository;
        }

        public RequestDetails Analyze(RequestSecurityToken rst, ClaimsPrincipal principal)
        {
            if (rst == null)
            {
                throw new ArgumentNullException("rst");
            }

            if (principal == null)
            {
                throw new ArgumentNullException("principal");
            }
            logger.Info("Starting PolicyOptions creation");
            logger.Info("Starting PolicyOptions creation");

            var clientIdentity = AnalyzeClientIdentity(principal);

            var details = new RequestDetails
            {
                ClientIdentity = clientIdentity,
                IsActive = false,
                Realm = null,
                IsKnownRealm = false,
                UsesSsl = false,
                UsesEncryption = false,
                ReplyToAddress = null,
                ReplyToAddressIsWithinRealm = false,
                IsReplyToFromConfiguration = false,
                EncryptingCertificate = null,
                ClaimsRequested = false,
                RequestClaims = null,
                Request = null,
                IsActAsRequest = false,
                RelyingPartyRegistration = null
            };

            AnalyzeRst(rst, details);
            AnalyzeTokenType(rst, details);
            AnalyzeKeyType(rst);
            AnalyzeRealm(rst, details);
            AnalyzeOperationContext(details);
            AnalyzeDelegation(rst, details);
            AnalyzeRelyingParty(details);
            AnalyzeEncryption(details);
            AnalyzeReplyTo(details);
            AnalyzeSsl(details);
            AnalyzeRequestClaims(details);

            logger.Info("PolicyOptions creation done.");

            _details = details;
            return details;
        }

        public void Validate()
        {
            Validate(_details);
        }

        public void Validate(RequestDetails details)
        {
            if (details == null)
            {
                throw new ArgumentNullException("details");
            }

            logger.Info("Starting policy validation");

            ValidateKnownRealm(details);
            ValidateRelyingParty(details);

            // not needed anymore
            //ValidateTokenType(details);

            ValidateReplyTo(details);
            ValidateEncryption(details);
            ValidateDelegation(details);

            logger.Info("Policy Validation succeeded");
        }

        #region Analyze
        protected virtual void AnalyzeRequestClaims(RequestDetails details)
        {
            // check if specific claims are requested
            if (details.Request.Claims != null && details.Request.Claims.Count > 0)
            {
                details.ClaimsRequested = true;
                details.RequestClaims = details.Request.Claims;

                var requestClaims = new StringBuilder(20);
                details.RequestClaims.ToList().ForEach(rq => requestClaims.AppendFormat("{0}\n", rq.ClaimType));
                logger.Info("Specific claims requested");
                logger.Info(String.Format("Request claims: {0}", requestClaims));
            }
            else
            {
                logger.Info("No request claims");
            }
        }

        protected virtual void AnalyzeSsl(RequestDetails details)
        {
            // determine if reply to is via SSL
            details.UsesSsl = (details.ReplyToAddress.Scheme == Uri.UriSchemeHttps);
            logger.Info(String.Format("SSL used:{0}", details.UsesSsl));
        }

        protected virtual void AnalyzeReplyTo(RequestDetails details)
        {
            var rp = details.RelyingPartyRegistration;

            // determine the reply to address (only relevant for passive requests)
            if (rp != null && rp.ReplyTo != null)
            {
                details.ReplyToAddress = rp.ReplyTo;
                details.IsReplyToFromConfiguration = true;

                // check if reply to is a sub-address of the realm address
                if (details.ReplyToAddress.AbsoluteUri.StartsWith(details.Realm.Uri.AbsoluteUri, StringComparison.OrdinalIgnoreCase))
                {
                    details.ReplyToAddressIsWithinRealm = true;
                }

                logger.Info(String.Format("ReplyTo Address set from configuration: {0}", details.ReplyToAddress.AbsoluteUri));
            }
            else
            {
                if (!String.IsNullOrEmpty(details.Request.ReplyTo))
                {
                    if (_configuration.WSFederation.AllowReplyTo)
                    {
                        // explicit address
                        details.ReplyToAddress = new Uri(details.Request.ReplyTo);
                        logger.Info(String.Format("Explicit ReplyTo address set: {0}", details.ReplyToAddress.AbsoluteUri));

                        // check if reply to is a sub-address of the realm address
                        if (details.ReplyToAddress.AbsoluteUri.StartsWith(details.Realm.Uri.AbsoluteUri, StringComparison.OrdinalIgnoreCase))
                        {
                            details.ReplyToAddressIsWithinRealm = true;
                        }

                        logger.Info(String.Format("ReplyTo Address is within Realm: {0}", details.ReplyToAddressIsWithinRealm));
                    }
                    else
                    {
                        // same as realm
                        details.ReplyToAddress = details.Realm.Uri;
                        details.ReplyToAddressIsWithinRealm = true;
                        logger.Warn(string.Format("ReplyTo address of ({0}) was supplied, but since configuration does not allow ReplyTo, the realm address is used", details.Request.ReplyTo));
                    }
                }
                else
                {
                    // same as realm
                    details.ReplyToAddress = details.Realm.Uri;
                    details.ReplyToAddressIsWithinRealm = true;
                    logger.Info("ReplyTo address set to realm address");
                }
            }
        }

        protected virtual void AnalyzeTokenType(RequestSecurityToken rst, RequestDetails details)
        {
            if (string.IsNullOrWhiteSpace(rst.TokenType))
            {
                details.TokenType = _configuration.Global.DefaultWSTokenType;
                logger.Info("Token Type: not specified, falling back to default token type");
            }
            else
            {
                logger.Info("Token Type: " + rst.TokenType);
                details.TokenType = rst.TokenType;
            }
        }

        protected virtual void AnalyzeEncryption(RequestDetails details)
        {
            if (details.EncryptingCertificate == null)
            {
                X509Certificate2 requestCertificate;
                if (TryGetEncryptionCertificateFromRequest(details.Realm, out requestCertificate))
                {
                    details.EncryptingCertificate = requestCertificate;
                    logger.Info("Encrypting certificate set from RST");
                }
            }

            details.UsesEncryption = (details.EncryptingCertificate != null);
            logger.Info("Token encryption: " + details.UsesEncryption);
        }

        protected virtual RelyingParty AnalyzeRelyingParty(RequestDetails details)
        {
            // check if the relying party is registered
            RelyingParty rp = null;
            if (RelyingPartyRepository.TryGet(details.Realm.Uri.AbsoluteUri, out rp))
            {
                details.RelyingPartyRegistration = rp;
                details.IsKnownRealm = true;

                var traceString = String.Format("Relying Party found in registry - Realm: {0}", rp.Realm.AbsoluteUri);

                if (!string.IsNullOrEmpty(rp.Name))
                {
                    traceString += String.Format(" ({0})", rp.Name);
                }

                logger.Info(traceString);

                if (rp.EncryptingCertificate != null)
                {
                    details.EncryptingCertificate = rp.EncryptingCertificate;
                    logger.Info("Encrypting certificate set from registry");
                }
            }
            else
            {
                logger.Info("Relying party is not registered.");
            }
            return rp;
        }

        protected virtual void AnalyzeDelegation(RequestSecurityToken rst, RequestDetails details)
        {
            // check for identity delegation request
            if (rst.ActAs != null)
            {
                details.IsActAsRequest = true;
                logger.Info("Request is ActAs request");
            }
        }

        protected virtual void AnalyzeKeyType(RequestSecurityToken rst)
        {
            if (!string.IsNullOrEmpty(rst.KeyType))
            {
                logger.Info(String.Format("Requested KeyType: {0}", rst.KeyType));
            }
        }

        protected virtual void AnalyzeOperationContext(RequestDetails details)
        {
            // determine if this is a WCF call
            if (OperationContext.Current != null)
            {
                details.IsActive = true;
                logger.Info("Active request");
            }
            else
            {
                logger.Info("Passive request");
            }
        }

        protected virtual ClaimsIdentity AnalyzeClientIdentity(ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException("principal");
            }

            if (principal.Identity == null)
            {
                throw new ArgumentNullException("identity");
            }

            var clientIdentity = principal.Identity as ClaimsIdentity;

            if (!clientIdentity.IsAuthenticated)
            {
                logger.Error("Client Identity is anonymous");
                throw new ArgumentException("client identity");
            }

            return clientIdentity;
        }

        protected virtual void AnalyzeRst(RequestSecurityToken rst, RequestDetails options)
        {
            if (rst == null)
            {
                throw new ArgumentNullException("request");
            }

            options.Request = rst;
        }

        protected virtual void AnalyzeRealm(RequestSecurityToken rst, RequestDetails options)
        {
            // check realm
            if (rst.AppliesTo == null || rst.AppliesTo.Uri == null)
            {
                throw new ArgumentNullException("AppliesTo");
                //throw new MissingAppliesToException("AppliesTo is missing");
            }

            options.Realm = new EndpointAddress(rst.AppliesTo.Uri);
        }
        #endregion

        #region Validate
        protected virtual void ValidateDelegation(RequestDetails details)
        {
            // check for ActAs request
            if (details.IsActAsRequest)
            {
                if (!_configuration.WSTrust.EnableDelegation)
                {
                    logger.Error("Request is ActAs request - but ActAs is not enabled");
                    throw new InvalidRequestException("Request is ActAs request - but ActAs is not enabled");
                }

                if (!DelegationRepository.IsDelegationAllowed(details.ClientIdentity.Name, details.Realm.Uri.AbsoluteUri))
                {
                    logger.Error(String.Format("ActAs mapping not found."));
                    throw new InvalidRequestException("ActAs mapping not found.");
                }
            }
        }

        private void ValidateTokenType(RequestDetails details)
        {
            if (details.TokenType == TokenTypes.SimpleWebToken || details.TokenType == TokenTypes.JsonWebToken)
            {
                if (details.RelyingPartyRegistration == null ||
                    details.RelyingPartyRegistration.SymmetricSigningKey == null ||
                    details.RelyingPartyRegistration.SymmetricSigningKey.Length == 0)
                {
                    logger.Error("Token with symmetric siganture requested, but no symmetric signing key found");
                    throw new InvalidRequestException("Token with symmetric siganture requested, but no symmetric signing key found");
                }
            }
        }

        protected virtual void ValidateEncryption(RequestDetails details)
        {
            // check if token must be encrypted
            if (_configuration.Global.RequireEncryption && (!details.UsesEncryption))
            {
                logger.Error("Configuration requires encryption - but no key available");
                throw new InvalidRequestException("No encryption key available");
            }
        }

        protected virtual void ValidateReplyTo(RequestDetails details)
        {
            // check if replyto is part of a registered realm (when not explicitly registered in config)
            if (!details.IsReplyToFromConfiguration)
            {
                if (_configuration.WSFederation.RequireReplyToWithinRealm && (!details.ReplyToAddressIsWithinRealm))
                {
                    logger.Error("Configuration requires that ReplyTo is a sub-address of the realm - this is not the case");
                    throw new InvalidRequestException("Invalid ReplyTo");
                }
            }
        }

        protected virtual void ValidateKnownRealm(RequestDetails details)
        {
            // check if realm is allowed
            if (_configuration.Global.RequireRelyingPartyRegistration && (!details.IsKnownRealm))
            {
                logger.Error("Configuration requires a known realm - but realm is not registered");

                throw new InvalidRequestException("Invalid realm: " + details.Realm.Uri.AbsoluteUri);
            }
        }

        protected virtual void ValidateRelyingParty(RequestDetails details)
        {
            if (details.RelyingPartyRegistration != null)
            {
                if (details.RelyingPartyRegistration.Enabled == false)
                {
                    logger.Error("Relying party is disabled");

                    throw new InvalidRequestException("Invalid realm: " + details.Realm.Uri.AbsoluteUri);
                }
            }
        }
        #endregion

        protected virtual bool TryGetEncryptionCertificateFromRequest(EndpointAddress appliesTo, out X509Certificate2 certificate)
        {
            if (appliesTo == null)
            {
                throw new ArgumentNullException("appliesTo");
            }

            certificate = null;

            var epi = appliesTo.Identity as X509CertificateEndpointIdentity;
            if (epi != null && epi.Certificates.Count > 0)
            {
                certificate = epi.GetEndCertificate();
                return true;
            }

            // no cert found
            return false;
        }
    }
}