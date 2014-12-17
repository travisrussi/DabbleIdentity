namespace Thinktecture.IdentityServer.Core.Repositories.Migrations.SqlServer
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class AddScopeToIdentityProvider : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.IdentityProvider", "Scope", c => c.String());
            AddColumn("dbo.IdentityProvider", "OpenIdProviderType", c => c.Int());
        }
        
        public override void Down()
        {
            DropColumn("dbo.IdentityProvider", "OpenIdProviderType");
            DropColumn("dbo.IdentityProvider", "Scope");
        }
    }
}
