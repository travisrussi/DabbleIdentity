using System;
namespace Thinktecture.IdentityServer.Web.Communication
{
    public interface ICommunicator : System.Web.Hosting.IRegisteredObject
    {
        void Start();
    }
}
