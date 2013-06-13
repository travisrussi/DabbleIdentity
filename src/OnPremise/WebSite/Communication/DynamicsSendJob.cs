using Microsoft.ServiceBus;
using Microsoft.ServiceBus.Messaging;
using Quartz;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web;
using System.Xml.Serialization;
using Thinktecture.IdentityServer.Repositories;
using NLog;
using System.Configuration;

namespace Thinktecture.IdentityServer.Web.Communication
{
    public class DynamicsSendJob : IJob
    {
        protected IUserManagementRepository UserManagementRepository;
        static Logger logger = LogManager.GetCurrentClassLogger();

        public DynamicsSendJob()
            : this(new ProviderUserManagementRepository()) //default
        {
        }

        public DynamicsSendJob(IUserManagementRepository rep)
        {
            UserManagementRepository = rep;
        }

        public virtual void Execute(IJobExecutionContext context)
        {
            try
            {
                logger.Log(LogLevel.Info, "Checking for Records to send");
                //logger.Log(LogLevel.Info, "Executing Sending Message Job");
                var queueName = ConfigurationManager.AppSettings["Microsoft.ServiceBus.SendQueueName"];
                var conn = ConfigurationManager.AppSettings["Microsoft.ServiceBus.ConnectionString"];
                var namespaceManager = NamespaceManager.CreateFromConnectionString(conn);

                //create a queue when not already exists
                if (!namespaceManager.QueueExists(queueName)) namespaceManager.CreateQueue(queueName);

                var records = UserManagementRepository
                    .VerifiedDirtyProfiles()
                    .Take(50); //max 50 records per execution / batch..
                //logger.Log(LogLevel.Info, "Records Found:" + records.Count());

                QueueClient client = QueueClient.CreateFromConnectionString(conn, queueName);
                foreach (var rec in records)
                {
                    try
                    {
                        logger.Log(LogLevel.Info, string.Format("Sending Record: {0}", rec.Email));
                        var message = GenerateProfileMessage(rec);
                        client.Send(message);
                        logger.Log(LogLevel.Info, string.Format("Record: {0} sent", rec.Email));

                        //after record sending succeed, set records back to clean.
                        rec.IsDirty = false;
                        UserManagementRepository.Update(rec);
                    }
                    catch (Exception ex)
                    {
                        logger.LogException(LogLevel.Error, string.Format("Sending record '{0}' failed", rec.Email), ex);
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogException(LogLevel.Error, string.Format("An Error Occured while trying to send a record"), ex);
            }
        }

        protected BrokeredMessage GenerateProfileMessage(Thinktecture.IdentityServer.Models.UserProfile profile)
        {   

            var messageProfile = new ProfileContract
            {
                city = profile.City,
                country = profile.Country.ToString(),
                email = profile.Email,
                externaluniquekey = string.IsNullOrWhiteSpace(profile.ExternalUniqueKey) ? Guid.Empty : Guid.Parse(profile.ExternalUniqueKey),
                firstname = profile.FirstName,
                housenumber = profile.HouseNumber,
                housenumberextension = profile.HouseNumberExtension,
                lastname = profile.LastName,
                middlename = profile.MiddleName,
                memberships = profile.OAuthMemberships != null ? profile.OAuthMemberships.ToDictionary(o => o.Provider, o=> o.ProviderUserId) : null,
                phonehome = profile.Phone,
                phonework = profile.PhoneWork,
                mobile = profile.PhoneMobile,
                postcode = profile.PostCode,
                salutation = profile.Salutation.ToString(),
                street = profile.Street,
                userid = profile.UserId,

                password = UserManagementRepository.GetPasswordHash(profile.UserId)
            };
            BrokeredMessage message = new BrokeredMessage(messageProfile);
            message.Properties.Add("system", "IDP");
            message.Properties.Add("userid", profile.UserId);

            return message;
        }
    }

    public class ProfileContract
    {
        public string email { get; set; }
        public string salutation { get; set; }
        public string firstname { get; set; }
        public string lastname { get; set; }
        public string middlename { get; set; }
        public string country { get; set; }
        public string postcode { get; set; }
        public int? housenumber { get; set; }
        public string housenumberextension { get; set; }
        public string street { get; set; }
        public string city { get; set; }
        public string phonehome { get; set; }
        public string phonework { get; set; }
        public string mobile { get; set; }

        public Guid externaluniquekey { get; set; }
        public int userid { get; set; }
        public string password { get; set; }

        public IDictionary<string, string> memberships { get; set; }
    }

}