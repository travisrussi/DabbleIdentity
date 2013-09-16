/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using System.Collections.Generic;
using System.Web.Mvc;
using Thinktecture.IdentityServer.Protocols;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.Web.ViewModels;
using System.Web.Security;
using WebMatrix.WebData;
using System.Transactions;
using System;
using Thinktecture.IdentityServer.Web.GlobalFilter;
using Thinktecture.IdentityServer.Models;
using System.ComponentModel.Composition;
using NLog;
using Microsoft.Web.WebPages.OAuth;
using System.IdentityModel.Services;

namespace Thinktecture.IdentityServer.Web.Controllers
{

    public class AccountController : AccountControllerBase
    {
        [Import]
        IUserManagementRepository UserManagementRepository;
        static Logger logger = LogManager.GetCurrentClassLogger();
        public AccountController()
        {
            Container.Current.SatisfyImportsOnce(this);
        }


        public AccountController(IUserRepository userRepository, IConfigurationRepository configurationRepository, IUserManagementRepository userManagementRepository)
            : base(userRepository, configurationRepository)
        {
            UserManagementRepository = userManagementRepository;
        }

        public ActionResult ConfirmAccount(string key, string user)
        {
            try
            {
                UserProfile profile = null;

                if (!string.IsNullOrEmpty(user) && !string.IsNullOrEmpty(key))
                {
                    //issue: do we want a limited time for a confirmation token to be valid?
                    //WebSecurity.GetCreateDate(user).AddDays(2) > DateTime.Now 
                    if (!WebSecurity.IsConfirmed(user))
                    {
                        profile = UserManagementRepository.GetUserProfileByConfirmationId(key, user);
                    }
                }
                //Issue: gives security risk if a user can login with a confirmationID
                if (profile != null)
                {
                    return SignIn(profile.Email,
                        AuthenticationMethods.Password,
                        string.Empty, //todo return url
                        false,
                        ConfigurationRepository.Global.SsoCookieLifetime);
                }
                else
                {

                    return RedirectToAction("Index", "Error", new { message = "An error occured, plz try again. if the problem persists contact the site administrator", area = "" });
                }
            }
            catch (Exception ex)
            {
                logger.LogException(LogLevel.Error, "An error occured while confirming account: ", ex);
                return RedirectToAction("Index", "Error", new { message = "An error occured, plz try again. if the problem persists contact the site administrator", area = "" });
            }

            return RedirectToAction("MyProfile");
        }

        [Authorize]
        public ActionResult RequestEmailChange()
        {
            try
            {
                UserManagementRepository.SendEmailChangeRequestEmail(HttpContext.User.Identity.Name);
            }
            catch (Exception e)
            {
                ModelState.AddModelError("", e.Message);
            }
            return RedirectToAction("MyProfile");
        }

        [Authorize]
        public ActionResult ConfirmNewEmail(string token)
        {

            string oldEmail = HttpContext.User.Identity.Name;
            string NewEmail = UserManagementRepository.GetNewEmailFromUser(oldEmail);
            bool userConfirmed = false;
            if (UserManagementRepository.ValidateTemporarilyValidGeneratedToken(oldEmail, token, EmailFunctionType.EmailAdressChangeConfirm))
            {
                if (UserManagementRepository.CheckUserForValidatedTokenOrValidateToken(oldEmail, token, EmailFunctionType.EmailAdressChangeConfirm))
                {
                    userConfirmed = true;
                }
                else
                {
                    ViewBag.ShowSucces = true;
                    ViewBag.Message = "You only need to confirm this" + oldEmail + " account";
                }

            }
            else if (UserManagementRepository.ValidateTemporarilyValidGeneratedToken(oldEmail, token, EmailFunctionType.EmailAdressChangeRequest))
            {
                if (UserManagementRepository.CheckUserForValidatedTokenOrValidateToken(oldEmail, token, EmailFunctionType.EmailAdressChangeRequest))
                {
                    userConfirmed = true;
                }
                else
                {
                    ViewBag.ShowSucces = true;
                    ViewBag.Message = "You only need to confirm this" + NewEmail + " account";
                }
            }
            else
            {
                return RedirectToAction("Index", "Error", new { message = "Invalid Token, please try to change your email again", area = "" });
            }
            if (userConfirmed)
            {

                if (string.IsNullOrEmpty(NewEmail))
                {
                    return RedirectToAction("Index", "Error", new { message = "Invalid Token, please try to change your email again", area = "" });
                }
                else
                {
                    var userProfile = UserManagementRepository.GetByUsername(oldEmail);
                    userProfile.Email = NewEmail;
                    userProfile.IsDirty = true;
                    UserManagementRepository.Update(userProfile);

                    ViewBag.ShowSucces = true;
                    ViewBag.Message = "Email Changed";
                    //Sign in again to override new cookie with new username
                    return SignIn(userProfile.Email,
                        AuthenticationMethods.Password,
                        string.Empty, //todo return url
                        false,
                        ConfigurationRepository.Global.SsoCookieLifetime);

                }
            }
            else
            {
                var profile = UserManagementRepository.GetByUsername(oldEmail);
                ViewBag.LocalAccount = OAuthWebSecurity.HasLocalAccount(WebSecurity.GetUserId(User.Identity.Name));
                return View("MyProfile", profile);
            }

        }

        //[Authorize]
        //public ActionResult EmailChange(string token)
        //{
        //    try
        //    {
        //        if (UserManagementRepository.ValidateTemporarilyValidGeneratedToken(HttpContext.User.Identity.Name, token, EmailFunctionType.EmailAdressChangeRequest))
        //        {
        //            return View();
        //        }
        //        else
        //        {
        //            return RedirectToAction("Index", "Error", new { message = "Invalid Token, Please request new email change url", area = "" });
        //        }
        //    }
        //    catch
        //    {
        //        return RedirectToAction("Index", "Error", new { message = "An error occured while trying to change your email adress", area = "" });
        //    }
        //}

        //public ActionResult ConfirmEmailChange(string token)
        //{
        //    return RedirectToAction("MyProfile");
        //}

        //[Authorize]
        //[HttpPost]
        //public ActionResult EmailChange(EmailChangeModel model)
        //{
        //    try
        //    {
        //        if (!WebSecurity.UserExists(model.UserName))
        //        {
        //            UserManagementRepository.SendEmailChangeConfirmationMail(model.UserName, HttpContext.User.Identity.Name);
        //            return RedirectToAction("MyProfile");
        //        }
        //        else
        //        {
        //            ModelState.AddModelError("", "User Exists");
        //            return View(model);
        //        }
        //    }
        //    catch (Exception e)
        //    {
        //        ModelState.AddModelError("", e.Message);
        //    }
        //    return View(model);
        //}

        [HttpPost]
        public ActionResult PasswordReset(PasswordResetModel model)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    UserProfile profile = UserManagementRepository.GetUserProfileByPasswordResetId(model.PasswordSecurityToken);
                    if (UserManagementRepository.ResetPassword(model.PasswordSecurityToken, model.Password))
                    {
                        if (profile != null)
                        {
                            return SignIn(profile.Email,
                                AuthenticationMethods.Password,
                                string.Empty, //todo return url
                                false,
                                ConfigurationRepository.Global.SsoCookieLifetime);
                        }
                    }
                }
                catch (Exception ex)
                {
                    logger.LogException(LogLevel.Error, "An error occured while resetting password: ", ex);
                }
            }
            //errormessage if token expired!
            ViewBag.DisplayInfoMessage = true;
            ViewBag.Message = "Reset Password Token Has Expired.";
            return View("SignIn");


        }

        public ActionResult PasswordReset(string key)
        {

            if (!string.IsNullOrEmpty(key))
            {
                return View(new PasswordResetModel() { PasswordSecurityToken = key });
            }
            //If no key is present just ignore it and redirect to homepage

            return View("SignIn");
        }

        //TODO: Implement this in the UserManagmentRepository
        [Authorize]
        public ActionResult Disassociate(string provider, string providerUserId)
        {
            string ownerAccount = OAuthWebSecurity.GetUserName(provider, providerUserId);
            // ManageMessageId? message = null;

            // Only disassociate the account if the currently logged in user is the owner
            if (ownerAccount == User.Identity.Name)
            {
                // Use a transaction to prevent the user from deleting their last login credential
                using (var scope = new TransactionScope(TransactionScopeOption.Required, new TransactionOptions { IsolationLevel = IsolationLevel.Serializable }))
                {
                    bool hasLocalAccount = OAuthWebSecurity.HasLocalAccount(WebSecurity.GetUserId(User.Identity.Name));
                    if (hasLocalAccount || OAuthWebSecurity.GetAccountsFromUserName(User.Identity.Name).Count > 1)
                    {
                        UserManagementRepository.DeleteOAuthAccount(provider, providerUserId);
                        scope.Complete();
                        // message = ManageMessageId.RemoveLoginSuccess;
                    }
                }
                UserManagementRepository.SetUserDirty(ownerAccount);
            }

            return RedirectToAction("MyProfile");
        }

        [Authorize]
        public ActionResult MyProfile()
        {
            try
            {
                //not needed authorize 
                if (HttpContext.User.Identity.IsAuthenticated)
                {
                    ViewBag.LocalAccount = OAuthWebSecurity.HasLocalAccount(WebSecurity.GetUserId(User.Identity.Name));
                    var profile = UserManagementRepository.GetByUsername(HttpContext.User.Identity.Name);
                    return View(profile);
                }
            }
            catch (Exception ex)
            {
                //todo: logging.
                logger.LogException(LogLevel.Error, "An error occured during opening the myprofile page: ", ex);
                System.Diagnostics.Debug.WriteLine("An error occured during opening the myprofile page : {0}", ex.Message);
            }

            return new HttpStatusCodeResult(System.Net.HttpStatusCode.Unauthorized);
        }


        //Get errormessaging from a language file.
        [HttpPost, Authorize, ValidateAntiForgeryToken]
        public ActionResult MyProfile(UserProfile model)
        {
            if (ModelState.IsValid)
            {
                //checking if the current logged in user is updating his/her profile.
                if (WebSecurity.IsCurrentUser(model.Email))
                {
                    model.IsDirty = true; //set to isdirty when user changes the model.
                    model.IsVerified = true;

                    try
                    {
                        UserManagementRepository.Update(model);
                        ViewBag.ShowSucces = true;
                    }
                    catch (Exception e)
                    {
                        logger.LogException(LogLevel.Error, "An error occured while trying to update user profile", e);
                        ViewBag.ShowSucces = false;
                        ViewBag.Message = "Er is een fout opgetreden tijden het wijzigen van uw profiel. Controleer uw gegevens en probeer het opnieuw";
                    }
                    try
                    {
                        //Changing Password if passwords have been filled
                        if (model.ChangePassword)
                        {
                            if (!string.IsNullOrEmpty(model.Password) && model.Password.Equals(model.Password2))
                            {
                                if (UserManagementRepository.ChangePassword(model.Email, model.CurrentPassword, model.Password))
                                {
                                    ViewBag.ShowSucces = true;
                                }
                                else
                                {
                                    ViewBag.ShowSucces = false;
                                    ViewBag.Message = "Er is een fout opgetreden tijdens het wijzigen van uw wachtwoord. Controleer uw gegevens en probeer het opnieuw";
                                }
                            }
                            else
                            {
                                ViewBag.ShowSucces = false;
                                ViewBag.Message = "Uw wachtoord velden zijn leeg";
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        logger.LogException(LogLevel.Error, "An error occured while trying to update user profile", e);
                        ViewBag.ShowSucces = false;
                        ViewBag.Message = "Er is een fout opgetreden tijdens het wijzigen van uw wachtwoord. Controleer uw gegevens en probeer het opnieuw";
                    }
                    if (model.ChangeEmail)
                    {
                        if (!string.IsNullOrEmpty(model.NewEmailAdress))
                        {
                            if (WebSecurity.UserExists(model.NewEmailAdress))
                            {
                                ViewBag.ShowSucces = false;
                                ViewBag.Message = "Er bestaat al een gebruiker met dit email adress: " + model.NewEmailAdress;
                            }
                            else
                            {
                                UserManagementRepository.SendEmailChangeRequestEmail(model.Email);
                                UserManagementRepository.SendEmailChangeConfirmationMail(model.NewEmailAdress, model.Email);
                            }
                        }
                    }

                }
            }
            else
            {
                ViewBag.ShowSucces = false;
                ViewBag.Message = "Er is een fout opgetreden tijden het wijzigen van uw profiel. Controleer uw gegevens en probeer het opnieuw";
            }
            var profile = UserManagementRepository.GetByUsername(model.Email);
            ModelState.Clear();
            ViewBag.LocalAccount = OAuthWebSecurity.HasLocalAccount(WebSecurity.GetUserId(User.Identity.Name));
            return View(profile); //be sure profile is loaded with latest data.
        }


        [Authorize]
        public ActionResult AddExternalIdentityProvider()
        {
            return View();
        }

        // shows the signin screen
        public ActionResult SignIn(string returnUrl, bool mobile = false)
        {
            // you can call AuthenticationHelper.GetRelyingPartyDetailsFromReturnUrl to get more information about the requested relying party
            if (WebSecurity.IsAuthenticated)
            {
                return RedirectToAction("MyProfile");
            }
            else
            {
                var vm = new CombinationLoginRegisterModel()
                {
                    ReturnUrl = returnUrl,
                    EnableSSO = true
                    //ShowClientCertificateLink = ConfigurationRepository.Global.EnableClientCertificateAuthentication
                };

                ViewData.Add("HideMenu", true);
                //if (mobile) vm.IsSigninRequest = true;
                return View(vm);
            }
        }

        // handles the signin
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult SignIn(CombinationLoginRegisterModel model)
        {

            if (ModelState.IsValid)
            {
                if (model.Registring)
                {
                    if (!string.IsNullOrEmpty(model.ConfirmPassword))
                    {
                        try
                        {
                            if (model.Password == model.ConfirmPassword)
                            {
                                UserManagementRepository.CreateUser(model.Email, model.Password);
                                ViewBag.DisplayInfoMessage = true;
                                ViewBag.Message = "Bedankt voor uw registratie, er is een bevestigingsmail verstuurd naar " + model.Email;
                                return View(new CombinationLoginRegisterModel());
                            }
                            else
                            {
                                ModelState.AddModelError("", "De door u ingevoerde wachtwoorden komen niet overeen. Probeer het nogmaals.");
                            }
                        }
                        catch (MembershipCreateUserException e)
                        {
                            ModelState.AddModelError("", ErrorCodeToString(e.StatusCode));
                        }
                        ViewData.Add("HideMenu", true);
                        // If we got this far, something failed, redisplay form
                        return View(model);
                    }
                }
                else
                {
                    if (UserRepository.ValidateUser(model.Email, model.Password))
                    {
                        // establishes a principal, set the session cookie and redirects
                        // you can also pass additional claims to signin, which will be embedded in the session token
                        return SignIn(
                            model.Email,
                            AuthenticationMethods.Password,
                            model.ReturnUrl,
                            model.EnableSSO,
                            ConfigurationRepository.Global.SsoCookieLifetime);
                    }
                }
            }

            ModelState.AddModelError("", Resources.AccountController.IncorrectCredentialsNoAuthorization);

            //model.ShowClientCertificateLink = ConfigurationRepository.Global.EnableClientCertificateAuthentication;
            ViewData.Add("HideMenu", true);
            return View(model);
        }

        // handles client certificate based signin
        public ActionResult CertificateSignIn(string returnUrl)
        {
            if (!ConfigurationRepository.Global.EnableClientCertificateAuthentication)
            {
                return new HttpNotFoundResult();
            }

            var clientCert = HttpContext.Request.ClientCertificate;

            if (clientCert != null && clientCert.IsPresent && clientCert.IsValid)
            {
                string userName;
                if (UserRepository.ValidateUser(new X509Certificate2(clientCert.Certificate), out userName))
                {
                    // establishes a principal, set the session cookie and redirects
                    // you can also pass additional claims to signin, which will be embedded in the session token

                    return SignIn(
                        userName,
                        AuthenticationMethods.X509,
                        returnUrl,
                        false,
                        ConfigurationRepository.Global.SsoCookieLifetime);
                }
            }

            return View("Error");
        }

        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        [AllowAnonymous]
        public ActionResult Forget()
        {
            ViewData.Add("HideMenu", true);
            return View();
        }

        [AllowAnonymous]
        public ActionResult Register()
        {
            ViewData.Add("HideMenu", true);
            return View();
        }

        [HttpPost]
        public ActionResult Forget(ForgotModel model)
        {
            if (ModelState.IsValid)
            {
                if (WebSecurity.IsConfirmed(model.UserName))
                {
                    UserManagementRepository.SendPasswordResetMail(model.UserName);
                    ViewBag.DisplayInfoMessage = true;
                    ViewBag.Message = "Bedankt voor uw verzoek. Er is een e-mail verstuurd waarmee u uw wachtwoord kunt wijzigen.";
                    return View("Signin");
                }
            }
            ModelState.AddModelError("", "De door u ingevoerde gegevens zijn onbekend. Probeer het nogmaals.");
            return View();
        }

        public PartialViewResult ShowInfoMessage(string Message)
        {
            ViewBag.Message = Message;
            return PartialView("InfoMessage");
        }


        private static string ErrorCodeToString(MembershipCreateStatus createStatus)
        {
            // See http://go.microsoft.com/fwlink/?LinkID=177550 for
            // a full list of status codes.
            switch (createStatus)
            {
                case MembershipCreateStatus.DuplicateUserName:
                    return "User name already exists. Please enter a different user name.";

                case MembershipCreateStatus.DuplicateEmail:
                    return "A user name for that e-mail address already exists. Please enter a different e-mail address.";

                case MembershipCreateStatus.InvalidPassword:
                    return "The password provided is invalid. Please enter a valid password value.";

                case MembershipCreateStatus.InvalidEmail:
                    return "The e-mail address provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidAnswer:
                    return "The password retrieval answer provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidQuestion:
                    return "The password retrieval question provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidUserName:
                    return "The user name provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.ProviderError:
                    return "The authentication provider returned an error. Please verify your entry and try again. If the problem persists, please contact your system administrator.";

                case MembershipCreateStatus.UserRejected:
                    return "The user creation request has been canceled. Please verify your entry and try again. If the problem persists, please contact your system administrator.";

                default:
                    return "An unknown error occurred. Please verify your entry and try again. If the problem persists, please contact your system administrator.";
            }
        }
        //#endregion
    }

}