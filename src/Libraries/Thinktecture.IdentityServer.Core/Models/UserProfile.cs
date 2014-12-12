using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Thinktecture.IdentityServer.Models
{
    public class UserProfile : IValidatableObject
    {
        [Claim]
        public int UserId { get; set; }

        [Mapper("emailaddress1")]
        [Required, RegularExpression(@"[A-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[A-z0-9](?:[A-z0-9-]*[A-z0-9])?\.)+[A-z0-9](?:[A-z0-9-]*[A-z0-9])?",
            @ErrorMessage = "Email adres is niet geldig.")
        ]

        [Claim]
        public string Email { get; set; }
        
        [RegularExpression(@"[A-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[A-z0-9](?:[A-z0-9-]*[A-z0-9])?\.)+[A-z0-9](?:[A-z0-9-]*[A-z0-9])?",
            @ErrorMessage = "Email adres is niet geldig.")
        ]
        public string NewEmail { get; set; }

        [Mapper("salutation")]
        [UIHint("Enum")]
         public SalutationEnum Salutation { get; set; }

        [Mapper("firstname")]
         public string FirstName { get; set; }

        [Mapper("lastname")]
        public string LastName { get; set; }

        [Mapper("middlename")]
        public string MiddleName { get; set; }

        /// <summary>
        /// Country ISO code
        /// </summary>
        [Mapper("address2_country")]
        [UIHint("Enum")]
        public CountryEnum Country { get; set; }

        [Mapper("address2_postalcode")]
        public string PostCode { get; set; }

        [RegularExpression(@"^([0-9]*)$")]
        [Mapper("address2_line2")]
        public int? HouseNumber { get; set; }

        [Mapper("address2_line3")]
        public string HouseNumberExtension { get; set; }

        [Mapper("address2_line1")]
        public string Street { get; set; }

        [Mapper("address2_city")]
         public string City { get; set; }

        [MaxLength(13)]
        [Mapper("mobilephone")]
        public string PhoneMobile { get; set; }

        [MaxLength(13)]
        [Mapper("telephone1")]
        public string PhoneWork { get; set; }

        [MaxLength(13)]
        [Mapper("telephone2")]
        public string Phone { get; set; }

        public bool IsDirty { get; set; }

        public bool IsVerified { get; set; }

        public bool ChangeEmail { get; set; }
        public bool ChangePassword { get; set; }

        [Claim]
        public string ExternalUniqueKey { get; set; }

        public string Password { get; set; }

        [Compare("Password", ErrorMessage = "Passwords don't match.")]
        public string Password2 { get; set; }

        public string CurrentPassword { get; set; }
        public string PasswordSecurityToken { get; set; }

        public string TemporarilyValidGeneratedToken { get; set; }

        public virtual ICollection<Role> Roles { get; set; }
        public virtual ICollection<OAuthMembership> OAuthMemberships { get; set; }        

        IEnumerable<ValidationResult> IValidatableObject.Validate(ValidationContext validationContext)
        {
            var results = new List<ValidationResult>();

            if (!string.IsNullOrEmpty(Password)
                && string.IsNullOrEmpty(Password) && string.IsNullOrEmpty(PasswordSecurityToken))
            {
                results.Add(new ValidationResult("You need to fill-in your current password, in order to get a new one."));
            }

            return results;
        }
    }

    public class Role
    {
        public int RoleId { get; set; }
        [StringLength(256)]
        public string RoleName { get; set; }
        public virtual ICollection<UserProfile> UserProfiles { get; set; }
    }

    public class OAuthMembership
    {
        [StringLength(30)]
        public string Provider { get; set; }
        [StringLength(100)]
        public string ProviderUserId { get; set; }
        public int? UserId { get; set; }
        public virtual UserProfile UserProfile { get; set; }
    }

    public enum SalutationEnum
    {
        Mr = 1,
        Mrs = 2,
        Miss = 3,
    }
    //Add your countries here
    public enum CountryEnum
    {
        Nederland = 1,
        Duitsland = 2,
        Belgie = 3,
        Frankrijk = 4,
    }
    //    public class Membership
    //    {
    //        [Key]
    //        public int UserId { get; set; }
    //        public DateTime? CreateDate { get; set; }
    //        [StringLength(128)]
    //        public string ConfirmationToken { get; set; }
    //        public bool? IsConfirmed { get; set; }
    //        public DateTime? LastPasswordFailureDate { get; set; }
    //        public int PasswordFailuresSinceLastSuccess { get; set; }
    //        [Required, StringLength(128)]
    //        public string Password { get; set; }
    //        public DateTime? PasswordChangedDate { get; set; }
    //        [Required, StringLength(128)]
    //        public string PasswordSalt { get; set; }
    //        [StringLength(128)]
    //        public string PasswordVerificationToken { get; set; }
    //        public DateTime? PasswordVerificationTokenExpirationDate { get; set; }
    //    }
}
