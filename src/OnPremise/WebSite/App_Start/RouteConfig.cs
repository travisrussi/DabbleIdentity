using System.Web.Mvc;
using System.Web.Routing;
using Thinktecture.IdentityServer.Repositories;

namespace Thinktecture.IdentityServer.Web
{
    public class RouteConfig
    {
        public static void RegisterRoutes(RouteCollection routes, IConfigurationRepository configuration, IUserRepository userRepository)
        {
            //TODO fix home routing
            routes.IgnoreRoute("{resource}.axd/{*pathInfo}");

            #region Administration & Configuration
            routes.MapRoute(
                "InitialConfiguration",
                "initialconfiguration",
                new { controller = "InitialConfiguration", action = "Index" }
            );

            //routes.MapRoute(
            //    "Admin",
            //    "admin/{action}/{id}",
            //    new { controller = "Admin", action = "Index", id = UrlParameter.Optional }
            //);

            //routes.MapRoute(
            //    "RelyingPartiesAdmin",
            //    "admin/relyingparties/{action}/{id}",
            //    new { controller = "RelyingPartiesAdmin", action = "Index", id = UrlParameter.Optional }
            //);

            //routes.MapRoute(
            //    "ClientCertificatesAdmin",
            //    "admin/clientcertificates/{action}/{userName}",
            //    new { controller = "ClientCertificatesAdmin", action = "Index", userName = UrlParameter.Optional }
            //);

            //routes.MapRoute(
            //    "DelegationAdmin",
            //    "admin/delegation/{action}/{userName}",
            //    new { controller = "DelegationAdmin", action = "Index", userName = UrlParameter.Optional }
            //);
            #endregion

            #region Main UI
            routes.MapRoute(
                "Account",
                "account/{action}/{id}",
                new { controller = "Account", action = "Index", id = UrlParameter.Optional }
            );

            routes.MapRoute(
                "Home",
                "{action}",
                new { controller = "Account", action = "SignIn", id = UrlParameter.Optional }
            );

            routes.MapRoute(
                "Error",
                "Error/{action}/{message}",
                new { controller = "Error", action = "Index", message = UrlParameter.Optional }
            );
            #endregion
        }

    }
}