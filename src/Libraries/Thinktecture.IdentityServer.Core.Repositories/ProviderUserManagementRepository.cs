using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Configuration.Provider;
using System.Linq;
using System.Web.Security;
using System.Web.Mvc;
using WebMatrix.WebData;
using Thinktecture.IdentityServer.Repositories.Sql;
using Microsoft.Web.WebPages.OAuth;
using Thinktecture.IdentityServer.Core.Repositories;
using Thinktecture.IdentityServer.Models;
using System;
using System.Text.RegularExpressions;
using System.Net;
using System.Net.Mail;
using SendGridMail;
using System.Configuration;
using NLog;
using Thinktecture.IdentityServer.Helper;
using System.Web;
using System.Web.Routing;

namespace Thinktecture.IdentityServer.Repositories
{
    public class ProviderUserManagementRepository : IUserManagementRepository
    {
        static Logger logger = LogManager.GetCurrentClassLogger();

        /// <summary>
        /// Make sure you put this method in a try catch(MembershipCreateUserException ex) so that u can catch exceptions and notify the user what went wrong;
        /// </summary>
        /// <param name="email">email is the username</param>
        /// <param name="password">password of the account</param>
        public void CreateUser(string email, string password)
        {
            if (Regex.IsMatch(email,
            @"^(?("")(""[^""]+?""@)|(([0-9a-z]((\.(?!\.))|[-!#\$%&'\*\+/=\?\^`\{\}\|~\w])*)(?<=[0-9a-z])@))" +
            @"(?(\[)(\[(\d{1,3}\.){3}\d{1,3}\])|(([0-9a-z][-\w]*[0-9a-z]*\.)+[a-z0-9]{2,17}))$",
            RegexOptions.IgnoreCase))
            {
                var confirmationToken = WebSecurity.CreateUserAndAccount(email, password,

                     new { Email = email, IsDirty = true, IsVerified = false, ExternalUniqueKey = Guid.NewGuid().ToString()}, true);
                SendConfirmationMail(email, confirmationToken);
            }
            else
            {
                throw new MembershipCreateUserException(MembershipCreateStatus.InvalidEmail);
            }
        }
        /// <summary>
        /// Url helper for generating MVC urls
        /// </summary>
        /// <returns>UrlHelper</returns>
        private UrlHelper GetUrlHelper()
        {
            var httpContextBase = new HttpContextWrapper(HttpContext.Current);
            var routeData = new RouteData();
            var requestContext = new RequestContext(httpContextBase, routeData);
            return new UrlHelper(requestContext);
        }

        /// <summary>
        /// generates a confirmation url for a user.
        /// </summary>
        /// <param name="email">user email</param>
        /// <param name="confirmationKey">generated confirmation key</param>
        /// <returns></returns>
        private string GenerateConfirmationUrl(string email, string confirmationKey)
        {
            var Url = GetUrlHelper();
            return Url.Action("ConfirmAccount", "Account", new { user = email, key = confirmationKey }, Url.RequestContext.HttpContext.Request.Url.Scheme);
        }
        /// <summary>
        /// generates a passwordReset url for a user
        /// </summary>
        /// <param name="passwordResetKey"></param>
        /// <returns></returns>
        private string GeneratePasswordResetUrl(string passwordResetKey)
        {
            var Url = GetUrlHelper();
            return Url.Action("PasswordReset", "Account", new { key = passwordResetKey }, Url.RequestContext.HttpContext.Request.Url.Scheme);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="emailChangeToken"></param>
        /// <returns></returns>
        private string GenerateEmailChangeurl(string emailChangeToken)
        {
            var Url = GetUrlHelper();
            return Url.Action("EmailChange", "Account", new { token = emailChangeToken }, Url.RequestContext.HttpContext.Request.Url.Scheme);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="emailChangeToken"></param>
        /// <returns></returns>
        private string GenerateConfirmNewEmailurl(string emailChangeToken)
        {
            var Url = GetUrlHelper();
            return Url.Action("ConfirmNewEmail", "Account", new { token = emailChangeToken }, Url.RequestContext.HttpContext.Request.Url.Scheme);
        }


        private void SendEmail(string body, string subject, string email)
        {
            SendGrid sendGridMessage = SendGrid.GetInstance();
            sendGridMessage.AddTo(email);
            sendGridMessage.From = new MailAddress("noreply@idp.com");
            sendGridMessage.Subject = subject;
            sendGridMessage.Text = body;
            // Create credentials, specifying your user name and password.
            var credentials = new NetworkCredential(ConfigurationManager.AppSettings["SendGrid.Username"]
                , ConfigurationManager.AppSettings["SendGrid.Password"]);

            // Create a Web transport for sending email.
            var transportWeb = SendGridMail.Transport.Web.GetInstance(credentials);

            // Send the email.
            transportWeb.Deliver(sendGridMessage);

        }

        //Todo make Email sending a utility Method
        /// <summary>
        /// sends a confirmation email with a confirmation url to the user
        /// </summary>
        /// <param name="email">email adress user</param>
        /// <param name="confirmationKey">confiration key</param>
        public void SendConfirmationMail(string email, string confirmationKey)
        {
            try
            {
                var url = GenerateConfirmationUrl(email, confirmationKey);
                string body = string.Format("To confirm your Account click this link: {0}", url);
                SendEmail(body, "account confirmation", email);

            }
            //Regurlar expression might fail, just in case an extra check here..
            catch (FormatException ex)
            {
                logger.LogException(LogLevel.Error, "EmailAdress Format incorrect removing User and returning invalid email adress exception", ex);
                DeleteUser(email);
                throw new MembershipCreateUserException(MembershipCreateStatus.InvalidEmail);
            }
            catch (Exception ex)
            {
                logger.LogException(LogLevel.Error, "An Error occured while trying to send an confirmation email, removing user and returning provider exception", ex);
                DeleteUser(email);
                throw new MembershipCreateUserException(MembershipCreateStatus.ProviderError);
            }
        }

        public void SendEmailChangeConfirmationMail(string newEmail, string oldEmail)
        {
            //Using the password reset token we can generate a temporary unique url where we can change the password
            string token = GenerateTemporaryValidToken(oldEmail, 30, EmailFunctionType.EmailAdressChangeConfirm);

            //Updating the new email in the database, we will set this email as username/main email when the validation link has been clicked
            try
            {
                using (var userContext = new UsersContext())
                {
                    var userProfile = userContext.UserProfiles.Where(u => u.Email.Equals(oldEmail)).FirstOrDefault();
                    userProfile.NewEmail = newEmail;
                    userContext.SaveChanges();
                }
            }
            catch (Exception e)
            {
                logger.LogException(LogLevel.Error, "An error occured while trying to add a NewEmail to a userprofile", e);
            }
            try
            {

                var subject = "Identity Provider Confirm Email Change";
                var url = GenerateConfirmNewEmailurl(token);
                var body = string.Format("To confirm your email change click this link: {0}", url);
                SendEmail(body, subject, newEmail);

            }
            catch (FormatException ex)
            {
                logger.LogException(LogLevel.Error, "EmailAdress Format incorrect Can't send confirm change emailadress, email", ex);
                throw new MembershipCreateUserException(MembershipCreateStatus.InvalidEmail);
            }
            catch (Exception ex)
            {
                logger.LogException(LogLevel.Error, "An Error occured while trying to send a confirm change emailadress, email", ex);
            }
        }

        public void SendEmailChangeRequestEmail(string email)
        {
            try
            {
                //Using the password reset token we can generate a temporary unique url where we can change the password
                string token = GenerateTemporaryValidToken(email, 30, EmailFunctionType.EmailAdressChangeRequest);

                var subject = "Identity Provider Email Change";
                var url = GenerateConfirmNewEmailurl(token);
                var body = string.Format("Your email has been changed too " + email);

                // Create credentials, specifying your user name and password.
                SendEmail(body, subject, email);
            }
            catch (Exception ex)
            {
                logger.LogException(LogLevel.Error, "An Error occured while trying to send a change emailadress request, email", ex);
                throw new Exception("An Error occured while trying to send a change email adress request email, please try again later. if this problem presists contact the web administrator");
            }
        }

        //Todo make Email sending a utility Method
        public void SendPasswordResetMail(string email)
        {
            string confirmationKey = WebSecurity.GeneratePasswordResetToken(email, 30);
            var subject = "Identity Provider password reset";
            var url = GeneratePasswordResetUrl(confirmationKey);
            var body = string.Format("To Reset your password click this link: {0}", url);
            SendEmail(body, subject, email);
        }

        /// <summary>
        /// Generates a temporaryValid token using a username and datetime from now.
        /// this token can be used as a variable in urls to identify valid users.
        /// Make sure to Remove the token after it has been used or when they are no longer valid
        /// </summary>
        /// <param name="userName">username</param>
        /// <param name="tokenExperationInMinutesFromNow">The ammount of minutes the token should be valid</param>
        /// <returns></returns>
        private string GenerateTemporaryValidToken(string userName, int tokenExperationInMinutesFromNow, EmailFunctionType type)
        {
            var token = string.Format("{0};{1};{2}", userName, DateTime.Now.AddMinutes(tokenExperationInMinutesFromNow), type.ToString()).Encrypt();
            using (var userContext = new UsersContext())
            {
                var userProfile = userContext.UserProfiles.Where(u => u.Email.Equals(userName)).FirstOrDefault();
                //If the token conaints a splitter it already has a set token, so just remove them and set it again
                if (!string.IsNullOrEmpty(userProfile.TemporarilyValidGeneratedToken))
                {
                    if (userProfile.TemporarilyValidGeneratedToken.Contains(';'))
                    {
                        userProfile.TemporarilyValidGeneratedToken = "";
                        userProfile.TemporarilyValidGeneratedToken = token;
                    }
                    else
                    {
                        userProfile.TemporarilyValidGeneratedToken += ";" + token;
                    }
                }
                else
                {
                    userProfile.TemporarilyValidGeneratedToken = token;
                }
                userContext.SaveChanges();
            }

            return token;
        }

        public void RemoveTemporaryValidToken(string userName, string token)
        {
            using (var userContext = new UsersContext())
            {
                var userProfile = userContext.UserProfiles.Where(u => u.Email.Equals(userName)).FirstOrDefault();
                if (!string.IsNullOrEmpty(userProfile.TemporarilyValidGeneratedToken))
                {
                    var tokens = userProfile.TemporarilyValidGeneratedToken.Split(';');
                    string validTokens = "";
                    foreach (var newtoken in tokens)
                    {
                        if (newtoken != token)
                        {
                            validTokens += newtoken + ";";
                        }
                    }
                    userProfile.TemporarilyValidGeneratedToken = validTokens.TrimEnd(';');
                }
                userContext.SaveChanges();
            }
        }


        /// <summary>
        /// Validates the temporarily generated token.
        /// User must be logged In to validate this token.
        /// </summary>
        /// <param name="userName">logged in userName</param>
        /// <param name="Token">temporarily generated token</param>
        /// <returns></returns>
        public bool ValidateTemporarilyValidGeneratedToken(string userName, string Token, EmailFunctionType type)
        {
            var decryptedToken = Token.Decrypt();
            DateTime dycriptedDate;
            if (decryptedToken.Split(';')[2].Equals(type.ToString()))
            {
                if (DateTime.TryParse(decryptedToken.Split(';')[1], out dycriptedDate))
                {
                    if (dycriptedDate > DateTime.Now)
                    {
                        using (var userContext = new UsersContext())
                        {
                            var userProfile = userContext.UserProfiles.Where(u => u.Email.Equals(userName)).FirstOrDefault();
                            var tokens = userProfile.TemporarilyValidGeneratedToken.Split(';');
                            foreach (var newToken in tokens)
                            {

                                if (newToken.Replace("Validated", "").Equals(Token))
                                {
                                    var dycripteduserName = decryptedToken.Split(';')[0];
                                    if (dycripteduserName == userName)
                                    {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            return false;
        }

        public bool CheckUserForValidatedTokenOrValidateToken(string email, string token, EmailFunctionType type)
        {
            using (var userContext = new UsersContext())
            {
                var userProfile = userContext.UserProfiles.Where(u => u.Email.Equals(email)).FirstOrDefault();
                var tokens = userProfile.TemporarilyValidGeneratedToken.Split(';');

                //We must make sure we can only have 1 validated token here
                var validToken = tokens.Where(t => t.EndsWith("Validated")).FirstOrDefault();
                var dycriptedvalidToken = string.IsNullOrEmpty(validToken) ? "" : validToken.Replace("Validated", "").Decrypt();
                if (string.IsNullOrEmpty(validToken))
                {
                    userProfile.TemporarilyValidGeneratedToken = userProfile.TemporarilyValidGeneratedToken.Replace(token, token + "Validated");
                    userContext.SaveChanges();
                    return false;
                }
                else
                {
                    if (dycriptedvalidToken.Split(';')[2].Equals(type.ToString()))
                    {
                        return false;
                    }
                    else
                    {
                        //Remove the tokens and return true
                        //if we want to use these tokens for more then just email change we must only remove the 2 email change tokens.
                        userProfile.TemporarilyValidGeneratedToken = "";
                        userContext.SaveChanges();
                        return true;
                    }
                }
            }
        }

        public bool ValidateEmailChange(string token, string email)
        {
            if (ValidateTemporarilyValidGeneratedToken(email, token, EmailFunctionType.EmailAdressChangeConfirm))
            {
                return CheckUserForValidatedTokenOrValidateToken(email, token, EmailFunctionType.EmailAdressChangeConfirm);

            }
            else if (ValidateTemporarilyValidGeneratedToken(email, token, EmailFunctionType.EmailAdressChangeRequest))
            {
                return CheckUserForValidatedTokenOrValidateToken(email, token, EmailFunctionType.EmailAdressChangeRequest);
            }
            else
            {
                return false;
            }
        }

        public string GetNewEmailFromUser(string email)
        {
            using (var userContext = new UsersContext())
            {
                return userContext.UserProfiles.Where(u => u.Email.Equals(email)).Select(u => u.NewEmail).FirstOrDefault();
            }

        }

        public void DeleteUser(string userName)
        {
            System.Web.Security.Membership.DeleteUser(userName, true);
        }

        public void SetRolesForUser(string userName, IEnumerable<string> roles)
        {
            var userRoles = Roles.GetRolesForUser(userName);

            if (userRoles.Length != 0)
            {
                Roles.RemoveUserFromRoles(userName, userRoles);
            }

            if (roles.Any())
            {
                Roles.AddUserToRoles(userName, roles.ToArray());
            }
        }

        public IEnumerable<string> GetRolesForUser(string userName)
        {
            return Roles.GetRolesForUser(userName);
        }

        public IEnumerable<string> GetRoles()
        {
            return Roles.GetAllRoles();
        }

        public void CreateRole(string roleName)
        {
            try
            {
                Roles.CreateRole(roleName);
            }
            catch (ProviderException)
            { }
        }

        public void DeleteRole(string roleName)
        {
            try
            {
                Roles.DeleteRole(roleName);
            }
            catch (ProviderException)
            { }
        }

        public IEnumerable<string> GetUsers(int start, int count, out int totalCount)
        {
            using (var userContext = new UsersContext())
            {
                var items = userContext.UserProfiles.Select(user => user.Email).ToList();
                totalCount = items.Count();
                return items;
            }
        }

        public IEnumerable<string> GetUsers(string filter, int start, int count, out int totalCount)
        {
            using (var userContext = new UsersContext())
            {
                var query =
                    from user in userContext.UserProfiles
                    where user.Email.Contains(filter) ||
                          (user.Email != null && user.Email.Contains(filter))
                    select user.Email;
                totalCount = query.Count();
                return query.OrderBy(e => e).Skip(start).Take(count).ToList();
            }
        }

        public IEnumerable<Models.UserProfile> VerifiedDirtyProfiles()
        {
            using (var userContext = new UsersContext())
            {
                return userContext.UserProfiles
                    .Where(u => u.IsVerified && u.IsDirty)
                    .ToList()
                    .Select(x => x.ToDomainModel()).ToList();
            }
        }

        /// <summary>
        /// Get profile based on username (emailaddress)
        /// </summary>
        /// <param name="username">username / emailaddress</param>
        /// <returns></returns>
        public Thinktecture.IdentityServer.Models.UserProfile GetByUsername(string username) //JWIJDE20130201, based on Thinktecture implementation..
        {
            using (var userContext = new UsersContext())
            {
                return userContext.UserProfiles.Where(u => u.Email.Equals(username))
                    .ToList()
                    .Select(x => x.ToDomainModel())
                    .FirstOrDefault();
            }
        }

        /// <summary>
        /// Gets a user based on their Unique Membership ID
        /// </summary>
        /// <param name="id">MemberShip Id</param>
        /// <returns>User Profile</returns>
        public Thinktecture.IdentityServer.Models.UserProfile GetByUserId(int id) //JWIJDE20130201, based on Thinktecture implementation..
        {
            using (var userContext = new UsersContext())
            {
                return userContext.UserProfiles.Where(u => u.UserId.Equals(id))
                    .ToList()
                    .Select(x => x.ToDomainModel())
                    .FirstOrDefault();
            }
        }

        //Handle valid tokenmanagment in controller for easy error messages to the user
        /// <summary>
        /// Confirms a user with a confirmationtoken and username(email) and then gets the UserProfile.
        /// If confirmation fails, returns null
        /// </summary>
        /// <param name="token">confirmation token</param>
        /// <param name="user"></param>
        /// <returns>User Profile or null if not found</returns>
        public Thinktecture.IdentityServer.Models.UserProfile GetUserProfileByConfirmationId(string token, string user)
        {

            if (WebSecurity.ConfirmAccount(user, token))
            {
                var profile = GetByUsername(user);
                //code for synchronization
                profile.IsVerified = true;
                Update(profile);
                return profile;
            }
            else
            {
                logger.Log(LogLevel.Info, "Account ConfirmationId Failed: " + user);
                return null;
            }

        }

        /// <summary>
        /// Gets a userProfile with use of the Temporary Generated passwordreset token
        /// </summary>
        /// <param name="token">password reset token</param>
        /// <returns>User Profile</returns>
        public Thinktecture.IdentityServer.Models.UserProfile GetUserProfileByPasswordResetId(string token)
        {
            int userid = WebSecurity.GetUserIdFromPasswordResetToken(token);
            var profile = GetByUserId(userid);
            return profile;
        }

        public bool ResetPassword(string token, string password)
        {
            return WebSecurity.ResetPassword(token, password);
        }

        /// <summary>
        /// Gets a user by the Unique Id from an external system.
        /// !Important Used only if you have your user Syncronized with an external system.
        /// </summary>
        /// <param name="externalKey">Unique external user Id</param>
        /// <returns>User Profile</returns>
        public Thinktecture.IdentityServer.Models.UserProfile GetByExternalKey(string externalKey)
        {
            using (var userContext = new UsersContext())
            {
                return userContext.UserProfiles.Where(u => u.ExternalUniqueKey.Equals(externalKey))
                    .ToList()
                    .Select(x => x.ToDomainModel())
                    .FirstOrDefault();
            }
        }

        /// <summary>
        /// Updates the user profile
        /// </summary>
        /// <param name="model">user profile model</param>
        public void Update(Thinktecture.IdentityServer.Models.UserProfile model)
        {
            if (model == null) throw new ArgumentException("model");

            using (var entities = new UsersContext())
            {
                var item = entities.UserProfiles.Where(u => u.UserId == model.UserId).Single();
                model.UpdateEntity(item);
                entities.SaveChanges();
            }
        }

        public IEnumerable<string> GetUsers(string filter)
        {
            using (var userContext = new UsersContext())
            {
                if (string.IsNullOrEmpty(filter))
                {
                    var items = userContext.UserProfiles.Select(user => user.Email).ToList();
                    return items;
                }
                else
                {
                    var items = userContext.UserProfiles.Where(e => e.Email.ToLower().Contains(filter.ToLower())).Select(e => e.Email).ToList();
                    return items;
                }
            }
        }

        /// <summary>
        /// Creates or or adds a user with an external identityprovider using AuthWebSecurity
        /// </summary>
        /// <param name="provider">Name of Identity Provider</param>
        /// <param name="providerUserId">User Id provided by the Identity Provider</param>
        /// <param name="email">Username (aka email) of the userIdentity</param>
        /// <returns>A bool if the update has succeded or not</returns>
        public bool CreateOrUpdateOAuthAccount(string provider, string providerUserId, string email)
        {
            using (UsersContext db = new UsersContext())
            {
                Thinktecture.IdentityServer.Repositories.Sql.UserProfile user = db.UserProfiles.FirstOrDefault(u => u.Email.ToLower() == email.ToLower());
                // Check if user already exists
                if (user == null)
                {
                    // Insert name into the profile table
                    db.UserProfiles.Add(new Thinktecture.IdentityServer.Repositories.Sql.UserProfile { Email = email, IsDirty = true, IsVerified = true });
                }
                else if (user.OAuthMemberships.Count > 0)
                {
                    foreach (var OAuthProvider in user.OAuthMemberships)
                    {
                        if (OAuthProvider.Provider == provider)
                        {
                            return false;
                        }
                    }
                }
                else
                {
                    user.IsDirty = true;

                }
                db.SaveChanges();

                OAuthWebSecurity.CreateOrUpdateAccount(provider, providerUserId, email);
                return true;
            }

        }

        public bool ChangePassword(string email, string currentPassword, string newPassword)
        {
            //change password only when filled

            bool hasLocalAccount = OAuthWebSecurity.HasLocalAccount(WebSecurity.GetUserId(email));
            if (hasLocalAccount)
            {
                return WebSecurity.ChangePassword(email, currentPassword, newPassword);
            }
            else
            {
                try
                {
                    WebSecurity.CreateAccount(email, newPassword);
                    return true;
                }
                catch (MembershipCreateUserException e)
                {
                    logger.LogException(LogLevel.Error, "An error occured while trying to create a local account for an OauthUser", e);
                    return false;
                }
            }

        }

        /// <summary>
        /// Removes an external Identity provider from a user
        /// </summary>
        /// <param name="provider">Name of Identity Provider</param>
        /// <param name="providerUserId">User Id provided by the Identity Provider</param>
        public void DeleteOAuthAccount(string provider, string providerUserId)
        {
            OAuthWebSecurity.DeleteAccount(provider, providerUserId);
        }


        public void SetUserDirty(string email)
        {
            using (UsersContext db = new UsersContext())
            {
                var user = db.UserProfiles.FirstOrDefault(u => u.Email.ToLower() == email.ToLower());
                user.IsDirty = true;
                db.SaveChanges();
            }
        }
        public string GetPasswordHash(int userid)
        {
            using (UsersContext db = new UsersContext())
            {
                return db.Database.SqlQuery<string>("select password from webpages_membership where userId = {0}", userid)
                    .FirstOrDefault();
            }
        }

        public string GetPasswordSalt(int userid)
        {
            using (UsersContext db = new UsersContext())
            {
                return db.Database.SqlQuery<string>("select passwordsalt from webpages_membership where userId = {0}", userid)
                    .FirstOrDefault();
            }
        }
    }
}
