using System.Web.Mvc;
using Thinktecture.IdentityServer.Web.GlobalFilter;

namespace Thinktecture.IdentityServer.Web
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());
            filters.Add(new GlobalViewModelFilter());
            filters.Add(new SslRedirectFilter(44300));
            filters.Add(new InitialConfigurationFilter());
           // filters.Add(new InitializeSimpleMembershipAttribute());
        }
    }
}