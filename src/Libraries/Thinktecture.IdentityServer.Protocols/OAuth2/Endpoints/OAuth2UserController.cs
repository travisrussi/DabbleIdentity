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
using Thinktecture.IdentityServer.Helper;
using NLog;
using System.Collections.Generic;
using System.Linq;
using WebMatrix.WebData;

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
            if (userRequest.Action.ToLower().Equals("accountcreate"))
            {
                return ProcessAccountCreateRequest(userRequest, tokenType, client);
            }
            else if (userRequest.Action.ToLower().Equals("profileget"))
            {
                return ProcessProfileGetRequest(userRequest, tokenType, client);
            }
            else if (userRequest.Action.ToLower().Equals("profileupdate"))
            {
                return ProcessProfileUpdateRequest(userRequest, tokenType, client);
            }
            else if (userRequest.Action.ToLower().Equals("passwordchange"))
            {
                return ProcessPasswordChangeRequest(userRequest, tokenType, client);
            }
            else if (userRequest.Action.ToLower().Equals("passwordresetrequest"))
            {
                return ProcessPasswordResetRequest(userRequest, tokenType, client);
            }
            else if (userRequest.Action.ToLower().Equals("passwordresetconfirm"))
            {
                return ProcessPasswordResetConfirmation(userRequest, tokenType, client);
            }
            else if (userRequest.Action.ToLower().Equals("emailconfirm"))
            {
                return ProcessEmailConfirmRequest(userRequest, tokenType, client);
            }
            
            var msg = "invalid action: " + userRequest.Action;
            logger.Error(msg);
            return OAuthErrorResponseMessage(msg);
        }

        private HttpResponseMessage ProcessAccountCreateRequest(UserRequest request, string tokenType, Client client)
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
                UserManagementRepository.CreateUser(request.Email, request.Password, null, request.FirstName, request.LastName);
                UserManagementRepository.SetRolesForUser(request.Email, new List<string> { Constants.Roles.IdentityServerUsers });
            }
            catch (Exception ex)
            {
                Tracing.Error("Resource owner credential creation failed: " + request.Email + " - " + ex.Message);
                return OAuthErrorResponseMessage(ex.Message);
            }

            if (UserRepository.ValidateUser(request.Email, request.Password))
            {
                var userProfile = UserManagementRepository.GetByUsername(request.Email);
                return CreateTokenResponse(userProfile, client, appliesTo, tokenType, includeRefreshToken: client.AllowRefreshToken);
            }
            else
            {
                msg = "Resource owner credential validation failed: " + request.Email;
                logger.Error(msg);
                return OAuthErrorResponseMessage(msg);
            }
        }

        private HttpResponseMessage ProcessProfileGetRequest(UserRequest request, string tokenType, Client client)
        {
            var msg = "Starting profile get request for client: " + client.Name;
            logger.Info(msg);
            var appliesTo = new EndpointReference(request.Scope);

            if (string.IsNullOrWhiteSpace(request.Email))
            {
                msg = "Invalid user credentials for: " + appliesTo.Uri.AbsoluteUri;
                logger.Error(msg);
                return OAuthErrorResponseMessage(msg);
            }

            try
            {
                var userProfile = UserManagementRepository.GetByUsername(request.Email);

                var resp = Request.CreateResponse<UserProfile>(HttpStatusCode.OK, userProfile);
                return resp;
            }
            catch (Exception ex)
            {
                Tracing.Error("Profile get request failed: " + request.Email + " - " + ex.Message);
                return OAuthErrorResponseMessage(ex.Message);
            }
        }

        private HttpResponseMessage ProcessProfileUpdateRequest(UserRequest request, string tokenType, Client client)
        {
            var msg = "Starting profile update for client: " + client.Name;
            logger.Info(msg);
            var appliesTo = new EndpointReference(request.Scope);

            if (string.IsNullOrWhiteSpace(request.Email))
            {
                msg = "Invalid profile update values for: " + appliesTo.Uri.AbsoluteUri;
                logger.Error(msg);
                return OAuthErrorResponseMessage(msg);
            }

            try
            {
                var userProfile = UserManagementRepository.GetByUsername(request.Email);
                if (userProfile != null)
                {
                    userProfile.FirstName = request.FirstName ?? userProfile.FirstName;
                    userProfile.LastName = request.LastName ?? userProfile.LastName;

                    if (!string.IsNullOrEmpty(request.EmailNew) && userProfile.Email != request.EmailNew)
                    {
                        var userProfileExisting = UserManagementRepository.GetByUsername(request.EmailNew);
                        if (userProfileExisting == null)
                        {
                            userProfile.Email = request.EmailNew;
                            userProfile.TemporarilyValidGeneratedToken = "";
                            userProfile.ChangeEmail = true;
                        }
                        else
                        {
                            msg = "Email address already exists (" + request.EmailNew + ")";
                            logger.Error(msg);
                            return OAuthErrorResponseMessage(msg);
                        }
                    }
                    UserManagementRepository.Update(userProfile);
                }

                userProfile = UserManagementRepository.GetByUsername(request.EmailNew);
                return CreateTokenResponse(userProfile, client, appliesTo, tokenType, includeRefreshToken: client.AllowRefreshToken);
            }
            catch (Exception e)
            {
                msg = "Profile update request failed: " + request.Email;
                logger.Error(msg, e);
                return OAuthErrorResponseMessage(msg);
            }
        }

        private HttpResponseMessage ProcessPasswordChangeRequest(UserRequest request, string tokenType, Client client)
        {
            var msg = "Starting password change for client: " + client.Name;
            logger.Info(msg);
            var appliesTo = new EndpointReference(request.Scope);

            if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrEmpty(request.Password) || string.IsNullOrEmpty(request.PasswordNew))
            {
                msg = "Invalid password change values for: " + appliesTo.Uri.AbsoluteUri;
                logger.Error(msg);
                return OAuthErrorResponseMessage(msg);
            }

            try
            {
                if (UserRepository.ValidateUser(request.Email, request.Password))
                {
                    string passwordResetToken = WebSecurity.GeneratePasswordResetToken(request.Email, 30);

                    if (UserManagementRepository.ResetPassword(passwordResetToken, request.PasswordNew))
                    {
                        return Request.CreateResponse<string>(HttpStatusCode.OK, null);
                    }
                    else
                    {
                        msg = "Change password failed with token: " + passwordResetToken;
                    }
                }
                else
                {
                    msg = "Invalid existing password";
                }

                logger.Error(msg);
                return Request.CreateResponse<string>(HttpStatusCode.OK, msg);
            }
            catch (Exception e)
            {
                msg = "Reset password request failed: " + request.Email;
                logger.Error(msg, e);
                return Request.CreateResponse<string>(HttpStatusCode.OK, msg);
            }
        }

        private HttpResponseMessage ProcessPasswordResetRequest(UserRequest request, string tokenType, Client client)
        {
            var msg = "Starting password reset for client: " + client.Name;
            logger.Info(msg);
            var appliesTo = new EndpointReference(request.Scope);

            if (string.IsNullOrWhiteSpace(request.Email))
            {
                msg = "Invalid password reset values for: " + appliesTo.Uri.AbsoluteUri;
                logger.Error(msg);
                return OAuthErrorResponseMessage(msg);
            }

            try
            {
                string passwordResetToken = WebSecurity.GeneratePasswordResetToken(request.Email, 30);

                var resp = Request.CreateResponse<string>(HttpStatusCode.OK, passwordResetToken);
                return resp;
            }
            catch (Exception e)
            {
                msg = "Reset password request failed: " + request.Email;
                logger.Error(msg, e);
                return OAuthErrorResponseMessage(msg);
            }
        }

        private HttpResponseMessage ProcessPasswordResetConfirmation(UserRequest request, string tokenType, Client client)
        {
            var msg = "Starting password reset confirmation for client: " + client.Name;
            logger.Info(msg);
            var appliesTo = new EndpointReference(request.Scope);

            if (string.IsNullOrWhiteSpace(request.Email))
            {
                msg = "Invalid password reset confirmation values for: " + appliesTo.Uri.AbsoluteUri;
                logger.Error(msg);
                return OAuthErrorResponseMessage(msg);
            }

            try
            {
                UserProfile userProfile = UserManagementRepository.GetUserProfileByPasswordResetId(request.Code);
                if (userProfile != null)
                {
                    if (UserManagementRepository.ResetPassword(request.Code, request.Password))
                    {
                        return CreateTokenResponse(userProfile, client, appliesTo, tokenType, includeRefreshToken: client.AllowRefreshToken);
                    }
                    else
                    {
                        msg = "Reset password request confirmation ResetPassword failed: " + request.Code;
                    }
                }
                else
                {
                    msg = "Reset password request confirmation failed because profile was not found for: " + request.Code;
                }

                logger.Error(msg);
                return OAuthErrorResponseMessage(msg);
            }
            catch (Exception e)
            {
                msg = "Reset password request confirmation failed: " + request.Email;
                logger.Error(msg, e);
                return OAuthErrorResponseMessage(msg);
            }
        }

        private HttpResponseMessage ProcessEmailConfirmRequest(UserRequest request, string tokenType, Client client)
        {
            var msg = "Starting email confirm for client: " + client.Name;
            logger.Info(msg);
            var appliesTo = new EndpointReference(request.Scope);

            if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Code))
            {
                msg = "Invalid email confirm values for: " + appliesTo.Uri.AbsoluteUri;
                logger.Error(msg);
                return OAuthErrorResponseMessage(msg);
            }

            try
            {
                //var userProfile = UserManagementRepository.GetByUsername(request.Email);
                //userProfile.NewEmail = request.NewEmail;

                ////Using the password reset token we can generate a temporary unique url where we can change the password
                string emailChangeToken = "";
                //string emailChangeToken = GenerateTemporaryValidToken(userProfile, 30, EmailFunctionType.EmailAdressChangeConfirm);

                ////If the token conaints a splitter it already has a set token, so just remove them and set it again
                //if (!string.IsNullOrEmpty(userProfile.TemporarilyValidGeneratedToken))
                //{
                //    if (userProfile.TemporarilyValidGeneratedToken.Contains(';'))
                //    {
                //        userProfile.TemporarilyValidGeneratedToken = "";
                //        userProfile.TemporarilyValidGeneratedToken = emailChangeToken;
                //    }
                //    else
                //    {
                //        userProfile.TemporarilyValidGeneratedToken += ";" + emailChangeToken;
                //    }
                //}
                //else
                //{
                //    userProfile.TemporarilyValidGeneratedToken = emailChangeToken;
                //}
                //UserManagementRepository.Update(userProfile);

                var resp = Request.CreateResponse<string>(HttpStatusCode.OK, emailChangeToken);
                return resp;
            }
            catch (Exception e)
            {
                msg = "Confirm email request failed: " + request.Email;
                logger.Error(msg, e);
                return OAuthErrorResponseMessage(msg);
            }
        }



        private HttpResponseMessage CreateTokenResponse(UserProfile userProfile, Client client, EndpointReference scope, string tokenType, bool includeRefreshToken)
        {
            var auth = new AuthenticationHelper();

            var principal = auth.CreatePrincipal(userProfile.Email, "OAuth2",
                    new Claim[]
                        {
                            new Claim(Constants.Claims.Client, client.Name),
                            new Claim(Constants.Claims.Scope, scope.Uri.AbsoluteUri),
                            new Claim("UserId", userProfile.UserId.ToString())
                        });

            if (!ClaimsAuthorization.CheckAccess(principal, Constants.Actions.Issue, Constants.Resources.OAuth2))
            {
                logger.Error("OAuth2 endpoint authorization failed for user: " + userProfile.Email);
                return OAuthErrorResponseMessage(OAuth2Constants.Errors.InvalidGrant);
            }

            var sts = new STS();
            TokenResponse tokenResponse;
            if (sts.TryIssueToken(scope, principal, tokenType, out tokenResponse))
            {
                if (includeRefreshToken)
                {
                    tokenResponse.RefreshToken = CodeTokenRepository.AddCode(CodeTokenType.RefreshTokenIdentifier, client.ID, userProfile.Email, scope.Uri.AbsoluteUri);
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
            if (!request.Action.ToLower().Equals("accountcreate") &&
                !request.Action.ToLower().Equals("profileget") &&
                !request.Action.ToLower().Equals("profileupdate") &&
                !request.Action.ToLower().Equals("passwordchange") && 
                !request.Action.ToLower().Equals("passwordresetrequest") &&
                !request.Action.ToLower().Equals("passwordresetconfirm") &&
                !request.Action.ToLower().Equals("emailconfirm"))
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

        /// <summary>
        /// Generates a temporaryValid token using a username and datetime from now.
        /// this token can be used as a variable in urls to identify valid users.
        /// Make sure to Remove the token after it has been used or when they are no longer valid
        /// </summary>
        /// <param name="userName">username</param>
        /// <param name="tokenExperationInMinutesFromNow">The ammount of minutes the token should be valid</param>
        /// <returns></returns>
        private string GenerateTemporaryValidToken(UserProfile userProfile, int tokenExperationInMinutesFromNow, EmailFunctionType type)
        {
            var token = string.Format("{0};{1};{2}", userProfile.Email, DateTime.Now.AddMinutes(tokenExperationInMinutesFromNow), type.ToString()).Encrypt();
            
            return token;
        }

    }
}
