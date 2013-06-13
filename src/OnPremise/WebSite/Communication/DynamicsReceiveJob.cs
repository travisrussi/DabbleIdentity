using Microsoft.ServiceBus.Messaging;
using Quartz;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Web;
using Thinktecture.IdentityServer;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Repositories;
using NLog;

//TODO implement simple sync between external user database
namespace Thinktecture.IdentityServer.Web.Communication
{
    public class DynamicsReceiveJob : IJob
    {
        protected IUserManagementRepository UserManagementRepository;
        static Logger logger = LogManager.GetCurrentClassLogger();
        public DynamicsReceiveJob()
            : this(new ProviderUserManagementRepository()) //default
        {
        }

        public DynamicsReceiveJob(IUserManagementRepository rep)
        {
            UserManagementRepository = rep;
        }

        public virtual void Execute(IJobExecutionContext context)
        {
     
        }
   
      
    }
}