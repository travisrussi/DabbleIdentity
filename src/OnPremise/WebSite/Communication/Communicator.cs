using Quartz;
using Quartz.Impl;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Web;
using System.Web.Hosting;

namespace Thinktecture.IdentityServer.Web.Communication
{
    
    public class Communicator<S, R> : ICommunicator
        where S : IJob
        where R : IJob
    {
        private IScheduler scheduler;

        public Communicator(IScheduler scheduler)
        {
            this.scheduler = scheduler;

            CreateJob<S>("SendUpdates", "Sending ID provider updates to CRM",
                b => b.WithIntervalInSeconds(20).RepeatForever());

            CreateJob<R>("ReceiveUpdates", "Receiving updates from the servicebus",
                b => b.WithIntervalInSeconds(20).RepeatForever());

            HostingEnvironment.RegisterObject(this);
        }

        /// <summary>
        /// Helper (factory) function to create and start a communicator with using default configuration settings.
        /// </summary>
        /// <returns></returns>
        public static Communicator<S, R> InitializeAndStart()
        {
            var config = new NameValueCollection();

            config["quartz.scheduler.instanceName"] = "CommunicationScheduler";
            config["quartz.threadPool.type"] = "Quartz.Simpl.SimpleThreadPool, Quartz";
            config["quartz.threadPool.threadCount"] = "5";
            config["quartz.threadPool.threadPriority"] = "Normal";
            config["quartz.scheduler.instanceId"] = "AUTO";
#if !DEBUG

            config["quartz.jobStore.type"] = "Quartz.Impl.AdoJobStore.JobStoreTX, Quartz";
            config["quartz.jobStore.driverDelegateType"] = "Quartz.Impl.AdoJobStore.StdAdoDelegate, Quartz"; 
            config["quartz.jobStore.useProperties"] = "true";
            config["quartz.jobStore.dataSource"] = "default";
            config["quartz.jobStore.tablePrefix"] = "QRTZ_";
            config["quartz.jobStore.lockHandler.type"] = "Quartz.Impl.AdoJobStore.UpdateLockRowSemaphore, Quartz";
            config["quartz.jobStore.clustered"] = "true";
#endif
            //if (RoleEnvironment.IsAvailable)
            //    config["quartz.dataSource.default.connectionString"] = "Server=.\\SQLEXPRESS;Database=;Trusted_Connection=True;";
            //else
            //TODO: get from web.config.
            config["quartz.dataSource.default.connectionString"] = "Server=tcp:dbfw1o5beb.database.windows.net;Database=Quartz;User ID=macaw_admin@dbfw1o5beb;Password=Telefax1;Trusted_Connection=False;Encrypt=True;";
            //config["quartz.dataSource.default.connectionString"] = "Server=.\\SQLEXPRESS;Database=;Trusted_Connection=True;";
            config["quartz.dataSource.default.provider"] = "SqlServer-20";

            var schedulerFactory = new StdSchedulerFactory(config);
            var scheduler = schedulerFactory.GetScheduler();

            var comm = new Communicator<S, R>(scheduler);
            comm.Start();
            return comm;
        }

        /// <summary>
        /// Start Executing scheduled jobs.
        /// </summary>
        public void Start()
        {
            scheduler.Start();
        }

        private void CreateJob<T>(string name, string group, Action<SimpleScheduleBuilder> action) where T : IJob
        {
            IJobDetail job = JobBuilder.Create<T>()
                .WithIdentity(name, group)
                .Build();
            
            TriggerKey key = new TriggerKey(string.Concat(name, " - ", "Trigger"));

            ITrigger trigger = TriggerBuilder.Create()
                .WithIdentity(key)
                .WithSimpleSchedule(action)
                .ForJob(job)
                .Build();
            

            scheduler.AddJob(job, true);

            if (!scheduler.CheckExists(key))
            {
                scheduler.ScheduleJob(trigger);
            }
        }

        /// <summary>
        /// Unregister object from hosting environment and shutdown scheduler immediate or wait until jobs are finished.
        /// </summary>
        /// <param name="immediate"></param>
        public void Stop(bool immediate)
        {
            if (immediate)
            {
                if (!scheduler.IsShutdown)
                    scheduler.Shutdown(false);
            }
            else
                scheduler.Shutdown(true);

            HostingEnvironment.UnregisterObject(this);
        }
    }
}