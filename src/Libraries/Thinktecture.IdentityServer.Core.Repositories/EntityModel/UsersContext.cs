using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data.Entity;

namespace Thinktecture.IdentityServer.Repositories.Sql
{
    public class UsersContext : DbContext
    {
        public DbSet<UserProfile> UserProfiles { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<OAuthMembership> OAuthMemberships { get; set; }
        public DbSet<Membership> Membership { get; set; }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            modelBuilder.Entity<UserProfile>()
            .HasMany<Role>(r => r.Roles)
            .WithMany(u => u.UserProfiles)
            .Map(m =>
            {
                m.ToTable("webpages_UsersInRoles");
                m.MapLeftKey("UserId");
                m.MapRightKey("RoleId");
            });

            modelBuilder.Entity<UserProfile>()
            .HasMany<OAuthMembership>(o => o.OAuthMemberships)
            .WithOptional(u => u.UserProfile)
            .HasForeignKey(k => k.UserId)
            .WillCascadeOnDelete(true);        
            
            base.OnModelCreating(modelBuilder);
        }

        public UsersContext()
            : base("name=ProviderDB")
        {
        }
    }

    [Table("UserProfile")]
    public class UserProfile
    {
        public UserProfile()
        {
            IsVerified = false;
            IsDirty = false;
        }

        [Key]
        [DatabaseGeneratedAttribute(DatabaseGeneratedOption.Identity)]
        public int UserId { get; set; }

        public string ExternalUniqueKey { get; set; }

        [Required]
        public string Email { get; set; }

        public string NewEmail { get; set; }

        public string Salutation { get; set; }

        public string FirstName { get; set; }

        public string LastName { get; set; }

        public string Surname { get; set; }

        public string Country { get; set; }

        public string PostCode { get; set; }

        public int? HouseNumber { get; set; }

        public string HouseNumberExtension { get; set; }

        public string Street { get; set; }

        public string City { get; set; }

        public string Phone { get; set; }
        public string PhoneWork { get; set; }
        public string PhoneMobile { get; set; }

        public bool IsDirty { get; set; }

        public bool IsVerified { get; set; }

        public string TemporarilyValidGeneratedToken { get; set; }

        public virtual ICollection<Role> Roles { get; set; }
        public virtual ICollection<OAuthMembership> OAuthMemberships { get; set; }

    }

    [Table("webpages_Roles")]
    public class Role
    {
        [Key]
        public int RoleId { get; set; }
        [StringLength(256)]
        public string RoleName { get; set; }
        public virtual ICollection<UserProfile> UserProfiles { get; set; }        
    }



    [Table("webpages_OAuthMembership")]
    public class OAuthMembership
    {
        [Key, Column(Order = 0), StringLength(30)]
        public string Provider { get; set; }
        [Key, Column(Order = 1), StringLength(100)]
        public string ProviderUserId { get; set; }
        public int? UserId { get; set; }
        public virtual UserProfile UserProfile {get; set; }
    }

    [Table("webpages_Membership")]
    public class Membership
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.None)]
        public int UserId { get; set; }
        public DateTime? CreateDate { get; set; }
        [StringLength(128)]
        public string ConfirmationToken { get; set; }
        public bool? IsConfirmed { get; set; }
        public DateTime? LastPasswordFailureDate { get; set; }
        public int PasswordFailuresSinceLastSuccess { get; set; }
        [Required, StringLength(128)]
        public string Password { get; set; }
        public DateTime? PasswordChangedDate { get; set; }
        [Required, StringLength(128)]
        public string PasswordSalt { get; set; }
        [StringLength(128)]
        public string PasswordVerificationToken { get; set; }
        public DateTime? PasswordVerificationTokenExpirationDate { get; set; }
    }
}
