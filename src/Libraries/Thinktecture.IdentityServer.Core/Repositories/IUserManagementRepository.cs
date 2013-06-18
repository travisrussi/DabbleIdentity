using System.Collections.Generic;

namespace Thinktecture.IdentityServer.Repositories
{
    public interface IUserManagementRepository
    {
        void CreateUser(string userName, string password);
        void DeleteUser(string userName);
        IEnumerable<string> GetUsers();
        IEnumerable<string> GetUsers(string filter);

        void SetRolesForUser(string userName, IEnumerable<string> roles);

        IEnumerable<string> GetRolesForUser(string userName);
        IEnumerable<string> GetRoles();

        void CreateRole(string roleName);
        void DeleteRole(string roleName);
        bool CreateOrUpdateOAuthAccount(string provider, string providerUserId, string userName);
        void DeleteOAuthAccount(string provider, string providerUserId);
        void SetUserDirty(string email);

        Thinktecture.IdentityServer.Models.UserProfile GetByUsername(string username);
        Thinktecture.IdentityServer.Models.UserProfile GetByExternalKey(string externalKey);

        void Update(Thinktecture.IdentityServer.Models.UserProfile model);
        IEnumerable<Models.UserProfile> VerifiedDirtyProfiles();
        Thinktecture.IdentityServer.Models.UserProfile GetUserProfileByConfirmationId(string id, string user);
        Thinktecture.IdentityServer.Models.UserProfile GetUserProfileByPasswordResetId(string id);

        bool ValidateTemporarilyValidGeneratedToken(string userName, string Token, Thinktecture.IdentityServer.Models.EmailFunctionType type);
        bool ResetPassword(string token, string password);
        bool ValidateEmailChange(string token, string email);
        void RemoveTemporaryValidToken(string userName, string token);
        bool CheckUserForValidatedTokenOrValidateToken(string email, string token, Thinktecture.IdentityServer.Models.EmailFunctionType type);

        void SendConfirmationMail(string email, string token);
        void SendPasswordResetMail(string email);
        void SendEmailChangeRequestEmail(string email);
        void SendEmailChangeConfirmationMail(string newEmail, string oldEmail);

        string GetNewEmailFromUser(string email);
        bool ChangePassword(string email, string currentPassword, string newPassword);
        string GetPasswordHash(int userid);
        string GetPasswordSalt(int userid);
    }
}
