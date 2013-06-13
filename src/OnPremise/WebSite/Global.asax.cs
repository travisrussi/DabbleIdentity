using Quartz;
using Quartz.Impl;
using System;
using System.Collections.Specialized;
using System.ComponentModel.Composition;
using System.ComponentModel.Composition.Hosting;
using System.Data.Entity;
using System.Security.Claims;
using System.Threading;
using System.Web.Helpers;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.Repositories.Sql;
using Thinktecture.IdentityServer.Web.GlobalFilter;
using Thinktecture.IdentityServer.Web.Communication;
using Thinktecture.IdentityServer.Web.Utility;
using NLog;
using Thinktecture.IdentityServer.DataAnnotationExtention;
using System.Web;
using Thinktecture.IdentityServer.Web.Controllers;
using System.Net.Http.Formatting;

namespace Thinktecture.IdentityServer.Web
{
    public class MvcApplication : System.Web.HttpApplication
    {
        ICommunicator Communicator;
        static Logger logger = LogManager.GetCurrentClassLogger();
        [Import]
        public IConfigurationRepository ConfigurationRepository { get; set; }

        [Import]
        public IUserRepository UserRepository { get; set; }

        [Import]
        public IRelyingPartyRepository RelyingPartyRepository { get; set; }

        protected void Application_Start()
        {
            // create empty config database if it not exists
            Database.SetInitializer(new ConfigurationDatabaseInitializer());
            ModelMetadataProviders.Current = new MetadataProvider();
            // set the anti CSRF for name (that's a unqiue claim in our system)
            AntiForgeryConfig.UniqueClaimTypeIdentifier = ClaimTypes.Name;

            // setup MEF
            SetupCompositionContainer();
            Container.Current.SatisfyImportsOnce(this);

            AreaRegistration.RegisterAllAreas();

            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes, ConfigurationRepository, UserRepository);
            ProtocolConfig.RegisterProtocols(GlobalConfiguration.Configuration, RouteTable.Routes, ConfigurationRepository, UserRepository, RelyingPartyRepository);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
            var authConfig = new AuthConfig();
            authConfig.RegisterAllIdentityProviders();            
            //Communicator = Communicator<DynamicsSendJob, DynamicsReceiveJob>.InitializeAndStart();
        }

        protected void Application_End()
        {
            //Communicator.Stop(true);
        }

        protected void Application_Error()
        {

                var exception = Server.GetLastError();
                var httpException = exception as HttpException;
                Response.TrySkipIisCustomErrors = true;
                Response.Clear();
                Server.ClearError();

                var routeData = new RouteData();
                routeData.Values["controller"] = "Error";
                routeData.Values["action"] = "General";
                routeData.Values["exception"] = exception;

                if (exception.Message.Equals("No route in the route table matches the supplied values."))
                {
                    Response.StatusCode = 404;
                    routeData.Values["action"] = "Http404";
                }
                if (httpException != null)
                {
                    Response.StatusCode = httpException.GetHttpCode();
                    switch (Response.StatusCode)
                    {
                        case 403:
                            routeData.Values["action"] = "Http403";
                            break;

                        case 404:
                            routeData.Values["action"] = "Http404";
                            break;

                        case 500:
                            routeData.Values["action"] = "General";
                            break;
                    }
                }
                else
                {
                    Response.StatusCode = 500;
                }

                // Avoid IIS7 getting in the middle
                IController errorController;

                errorController = new ErrorController();
                
                var wrapper = new HttpContextWrapper(Context);
                var rc = new RequestContext(wrapper, routeData);
                errorController.Execute(rc);
   
        }

        private void SetupCompositionContainer()
        {
            Container.Current = new CompositionContainer(new RepositoryExportProvider());
        }
    }
}