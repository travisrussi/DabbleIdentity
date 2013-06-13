using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Profile;

namespace Thinktecture.IdentityServer.Core.MembershipExtention
{
    public class CustomMembershipProfile : ProfileBase
    {

        /** Extending Membership with these Properties:
         * 
         * Salutation (Mr. / Miss. / Mrs. ect)
         * FirstName 
         * LastName
         * Surname (van , van der, ect.)
         * Country
         * City
         * PostCode
         * HouseNumber
         * Street
         * Phone
         * 
         * */
        public CustomMembershipProfile()
        {
        }

        public string Salutation
        {
            get
            {
                return this.GetPropertyValue("Salutation") as string;
            }
            set
            {
                this.SetPropertyValue("Salutation", value);
            }
        }

        public string FirstName
        {
            get
            {
                return this.GetPropertyValue("FirstName") as string;
            }
            set
            {
                this.SetPropertyValue("FirstName", value);
            }
        }

        public string LastName
        {
            get
            {
                return this.GetPropertyValue("LastName") as string;
            }
            set
            {
                this.SetPropertyValue("LastName", value);
            }
        }

        public string Surname
        {
            get
            {
                return this.GetPropertyValue("Surname") as string;
            }
            set
            {
                this.SetPropertyValue("Surname", value);
            }
        }

        public string Country
        {
            get
            {
                return this.GetPropertyValue("Country") as string;
            }
            set
            {
                this.SetPropertyValue("Country", value);
            }
        }

        public string PostCode
        {
            get
            {
                return this.GetPropertyValue("PostCode") as string;
            }
            set
            {                
                this.SetPropertyValue("PostCode", value);
            }
        }

        public int? HouseNumber
        {
            get
            {
                return this.GetPropertyValue("HouseNumber") as int?;
            }
            set
            {           
                this.SetPropertyValue("HouseNumber", value);
            }
        }


        public string Street
        {
            get
            {
                return this.GetPropertyValue("Street") as string;
            }
            set
            {           
                this.SetPropertyValue("Street", value);
            }
        }


        public string City
        {
            get
            {
                return this.GetPropertyValue("City") as string;
            }
            set
            {           
                this.SetPropertyValue("City", value);
            }
        }

        public string Phone
        {
            get
            {
                return this.GetPropertyValue("Phone") as string;
            }
            set
            {           
                this.SetPropertyValue("Phone", value);
            }
        }

    }
}


