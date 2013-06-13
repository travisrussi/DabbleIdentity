using System.ComponentModel.DataAnnotations;
using System.Data.Entity.Migrations;

namespace Thinktecture.IdentityServer.Repositories.Sql
{
    public class IdentityProvider
    {
        [Key]
        public int ID { get; set; }

        [Required]
        public string Name { get; set; }

        [Required]
        public string DisplayName { get; set; }

        public int Type { get; set; }

        [Required]
        public bool ShowInHrdSelection { get; set; }

        public string WSFederationEndpoint { get; set; }
        public string IssuerThumbprint { get; set; }

        public string ClientID { get; set; }
        public string ClientSecret { get; set; }
        public string Scope { get; set; }
        public int? OAuth2ProviderType { get; set; }
        public int? OpenIdProviderType { get; set; }

        public bool Enabled { get; set; }
    }

    public partial class AddOpenIdProviderType : DbMigration
    {
        public override void Up()
        {
            AddColumn("IdentityProvider", "OpenIdProviderType", c => c.Int());
        }

        public override void Down()
        {
            DropColumn("IdentityProvider", "OpenIdProviderType");

        }

    }
}