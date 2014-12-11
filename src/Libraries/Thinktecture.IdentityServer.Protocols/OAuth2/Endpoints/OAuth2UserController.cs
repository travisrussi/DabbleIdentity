/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.ComponentModel.Composition;
using System.IdentityModel.Protocols.WSTrust;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using Thinktecture.IdentityModel.Authorization;
using Thinktecture.IdentityModel.Constants;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Repositories;
using NLog;
using System.Collections.Generic;

namespace Thinktecture.IdentityServer.Protocols.OAuth2
{
    public class OAuth2UserController : ApiController
    {
        static Logger logger = LogManager.GetCurrentClassLogger();

        [Import]
        public IUserRepository UserRepository { get; set; }

        [Import]
        public IUserManagementRepository UserManagementRepository { get; set; }

        [Import]
        public IConfigurationRepository ConfigurationRepository { get; set; }

        [Import]
        public IClientsRepository ClientsRepository { get; set; }

        [Import]
        public ICodeTokenRepository CodeTokenRepository { get; set; }

        public OAuth2UserController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }

        public OAuth2UserController(IUserRepository userRepository, IUserManagementRepository userManagementRepository, IConfigurationRepository configurationRepository, IClientsRepository clientsRepository, ICodeTokenRepository codeTokenRepository)
        {
            UserRepository = userRepository;
            UserManagementRepository = userManagementRepository;
            ConfigurationRepository = configurationRepository;
            ClientsRepository = clientsRepository;
            CodeTokenRepository = codeTokenRepository;
        }

        public HttpResponseMessage Post([FromBody] UserRequest userRequest)
        {
            logger.Info("OAuth2 endpoint called.");

            Client client = null;
            var error = ValidateRequest(userRequest, out client);
            if (error != null) return error;

            logger.Info("Client: " + client.Name);

            // read token type from configuration (typically JWT)
            var tokenType = ConfigurationRepository.Global.DefaultHttpTokenType;

            // switch over the grant type
            if (userRequest.Action.ToLower().Equals("create"))
            {
                return ProcessCreateRequest(userRequest, tokenType, client);
            }

            var msg = "invalid action: " + userRequest.Action;
            logger.Error(msg);
            return OAuthErrorResponseMessage(msg);
        }

        private HttpResponseMessage ProcessCreateRequest(UserRequest request, string tokenType, Client client)
        {
            var msg = "Starting create user for client: " + client.Name;
            logger.Info(msg);
            var appliesTo = new EndpointReference(request.Scope);

            if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
            {
                msg = "Invalid create user credentials for: " + appliesTo.Uri.AbsoluteUri;
                logger.Error(msg);
                return OAuthErrorResponseMessage(msg);
            }

            try
            {
                UserManagementRepository.CreateUser(request.Email, request.Password, request.ExternalUniqueKey);
                UserManagementRepository.SetRolesForUser(request.Email, new List<string> { Constants.Roles.IdentityServerUsers });
            }
            catch (Exception ex)
            {
                Tracing.Error("Resource owner credential creation failed: " + request.Email + " - " + ex.Message);
                return OAuthErrorResponseMessage(ex.Message);
            }

            if (UserRepository.ValidateUser(request.Email, request.Password))
            {
                return CreateTokenResponse(request.Email, client, appliesTo, tokenType, includeRefreshToken: client.AllowRefreshToken);
            }
            else
            {
                msg = "Resource owner credential validation failed: " + request.Email;
                logger.Error(msg);
                return OAuthErrorResponseMessage(msg);
            }
        }

        private HttpResponseMessage CreateTokenResponse(string userName, Client client, EndpointReference scope, string tokenType, bool includeRefreshToken)
        {
            var auth = new AuthenticationHelper();

            var principal = auth.CreatePrincipal(userName, "OAuth2",
                    new Claim[]
                        {
                            new Claim(Constants.Claims.Client, client.Name),
                            new Claim(Constants.Claims.Scope, scope.Uri.AbsoluteUri)
                        });

            if (!ClaimsAuthorization.CheckAccess(principal, Constants.Actions.Issue, Constants.Resources.OAuth2))
            {
                logger.Error("OAuth2 endpoint authorization failed for user: " + userName);
                return OAuthErrorResponseMessage(OAuth2Constants.Errors.InvalidGrant);
            }

            var sts = new STS();
            TokenResponse tokenResponse;
            if (sts.TryIssueToken(scope, principal, tokenType, out tokenResponse))
            {
                if (includeRefreshToken)
                {
                    tokenResponse.RefreshToken = CodeTokenRepository.AddCode(CodeTokenType.RefreshTokenIdentifier, client.ID, userName, scope.Uri.AbsoluteUri);
                }

                var resp = Request.CreateResponse<TokenResponse>(HttpStatusCode.OK, tokenResponse);
                return resp;
            }
            else
            {
                return OAuthErrorResponseMessage(OAuth2Constants.Errors.InvalidRequest);
            }
        }

        private HttpResponseMessage OAuthErrorResponseMessage(string error)
        {
            return Request.CreateErrorResponse(HttpStatusCode.BadRequest,
                string.Format("{{ \"{0}\": \"{1}\" }}", OAuth2Constants.Errors.Error, error));
        }

        private HttpResponseMessage ValidateRequest(UserRequest request, out Client client)
        {
            client = null;

            if (request == null)
            {
                return OAuthErrorResponseMessage(OAuth2Constants.Errors.InvalidRequest);
            }

            // grant type is required
            if (string.IsNullOrWhiteSpace(request.Action))
            {
                return OAuthErrorResponseMessage("Unsupported Action");
            }

            // check supported grant types
            if (!request.Action.ToLower().Equals("create") &&
                !request.Action.ToLower().Equals("profile"))
            {
                return OAuthErrorResponseMessage("Unsupported Action");
            }

            // user flow requires a well-formed scope
            Uri appliesTo;
            if (!Uri.TryCreate(request.Scope, UriKind.Absolute, out appliesTo))
            {
                logger.Error("Malformed scope: " + request.Scope);
                return OAuthErrorResponseMessage(OAuth2Constants.Errors.InvalidScope);
            }

            logger.Info("OAuth2 endpoint called for scope: " + request.Scope);
            
            if (!ValidateClient(out client))
            {
                logger.Error("Invalid client: " + ClaimsPrincipal.Current.Identity.Name); 
                return OAuthErrorResponseMessage(OAuth2Constants.Errors.InvalidClient);
            }

            return null;
        }

        private bool ValidateClient(out Client client)
        {
            client = null;

            if (!ClaimsPrincipal.Current.Identity.IsAuthenticated)
            {
                logger.Error("Anonymous client.");
                return false;
            }

            var passwordClaim = ClaimsPrincipal.Current.FindFirst("password");
            if (passwordClaim == null)
            {
                logger.Error("No client secret provided.");
                return false;
            }

            return ClientsRepository.ValidateAndGetClient(
                ClaimsPrincipal.Current.Identity.Name,
                passwordClaim.Value,
                out client);
        }
    }
}
