using Microsoft.ServiceBus;
using Microsoft.ServiceBus.Messaging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.WindowsAzure;
using Moq;
using Quartz;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Thinktecture.IdentityServer.Models;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.Web.Communication;

namespace Tests.Unit_Tests
{
    /// <summary>
    /// Class with tests for DynamicsReceiveJob
    /// Naming convention: MethodNameToTest_StateUnderTest_ExpectedBehavior
    /// </summary>
    [TestClass]
    public class DynamicsReceiveJobTest
    {
        /// <summary>
        /// This function can only run when a test queue is available. 
        /// When a disconnected profile has been sent to IDP a profile has to be found based on the username / emailaddress
        /// Because profile isn't dirty, IDP data become equal to the CRM data. 
        /// </summary>
        [TestMethod]
        public void Execute_RecordAvailableOnServiceBus_IDPDataEqualToCRMData()
        {
            //1. Arrange
            var Repository = new Mock<IUserManagementRepository>();
            Repository.Setup(r => r.GetByUsername("thijs.de.tester@macaw.nl"))
                .Returns(new Thinktecture.IdentityServer.Models.UserProfile
                {
                    UserId = 1001,
                    Email = "thijs.de.tester@macaw.nl",
                    IsVerified = true,
                    IsDirty = true
                });

            var job = new DynamicsReceiveJob(Repository.Object);
            var context = new Mock<IJobExecutionContext>();

            //2. Act
            job.Execute(context.Object);

            //3. Assert
            Repository.Verify(r => r.Update(It.Is<Thinktecture.IdentityServer.Models.UserProfile>(u =>
                u.FirstName.Equals("Thijs") 
                && u.LastName.Equals("Tester") 
                && !string.IsNullOrEmpty(u.ExternalUniqueKey)
                && u.HouseNumber.HasValue))); //the user is synced
            //because we can't find the user based on the external id, we have to find it by username
            Repository.Verify(r => r.GetByUsername("thijs.de.tester@macaw.nl"));
        }
    }

    [TestClass]
    public class DynamicsSendJobTest
    {
        
        /// <summary>
        /// 
        /// </summary>
        [TestMethod]
        public void Execute_SeveralRecordsInDB3AvailableForSending_CleanVerfiedDirtyRecords()
        {
            //1. Arrange
            //var Original = new ProviderUserManagementRepository();
            var Repository = new Mock<IUserManagementRepository>();

            Repository.Setup(r => r.GetPasswordHash(It.IsAny<int>()))
                .Returns(() =>
                {
                    return "zcA-password//hash-SDFzcvxxx";
                });

            
            Repository.Setup(r => r.VerifiedDirtyProfiles())
                .Returns(() => 
                {
                    var ret = new List<Thinktecture.IdentityServer.Models.UserProfile>();
                    
                    ret.Add(new Thinktecture.IdentityServer.Models.UserProfile
                    {
                        UserId = 1001,
                        Email = "thijs.de.tester@macaw.nl"
                    }); //this is the only record that will be sent to the queue...

                    ret.Add(CreateProfileMock(1002, "joost.de.tester@macaw.nl", "Joost", "de", "Tester"));
                    ret.Add(CreateProfileMock(1002, "frank.beheerder@macaw.nl", "Frank", null, "Beheerder"));

                    return ret;
                });

            var job = new DynamicsSendJob(Repository.Object);
            var context = new Mock<IJobExecutionContext>();

            //2. Act
            job.Execute(context.Object);

            //3. Assert
            Repository.Verify(r => r.Update(It.Is<Thinktecture.IdentityServer.Models.UserProfile>(u =>
                u.Email.Equals("thijs.de.tester@macaw.nl"))));

            //Assertion on Queue
            var conn = CloudConfigurationManager.GetSetting("Microsoft.ServiceBus.ConnectionString");
            var queueName = CloudConfigurationManager.GetSetting("Microsoft.ServiceBus.SendQueueName");
            var namespaceManager = NamespaceManager.CreateFromConnectionString(conn);

            
            MessagingFactory mfactory = MessagingFactory.CreateFromConnectionString(conn);
            MessageReceiver receiver = mfactory.CreateMessageReceiver(queueName, ReceiveMode.PeekLock);
            BrokeredMessage message;
            ProfileContract user = null;
            while ((message = receiver.Receive(new TimeSpan(hours: 0, minutes: 0, seconds: 20))) != null)
            {
                user = message.GetBody<ProfileContract>();
                message.Complete();
            }

            //assert email address of latest record.
            Assert.IsTrue(user != null && user.email.Equals("frank.beheerder@macaw.nl"), "There has to be one userprofile in the queue");
        }

        public UserProfile CreateProfileMock(int userId, string email, string firstname, string middlename, string lastname)
        {
            
            var ret = new Thinktecture.IdentityServer.Models.UserProfile {
                City = "Amsterdam",
                Country = CountryEnum.Nederland,
                Email = email,
                ExternalUniqueKey =  string.Format("fcefa537-6f8a-e211-92b9-00155d805b20", userId),
                FirstName = firstname,
                HouseNumber = 50,
                HouseNumberExtension = "a",
                LastName = lastname,
                MiddleName = middlename,
                Phone = "06-12345678",
                PostCode = "1234 AA",
                Salutation = SalutationEnum.heer,
                Street = "Luchthavenweg",
                UserId = userId,

                IsVerified = true,
                IsDirty = true
            };

            ret.OAuthMemberships = new List<OAuthMembership>();

            ret.OAuthMemberships.Add(new OAuthMembership { Provider = "facebook", ProviderUserId = "some-id-in-face-book-123", UserId = userId, UserProfile = ret });
            ret.OAuthMemberships.Add(new OAuthMembership { Provider = "google", ProviderUserId = "some-id-in-google", UserId = userId, UserProfile = ret });

            return ret;
        }
    }
}
