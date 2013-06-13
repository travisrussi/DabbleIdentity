using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Thinktecture.IdentityServer.Models
{
    public class MapperAttribute : Attribute
    {
        public MapperAttribute(string propertyname)
        {
            _propertyName = propertyname;
        }

        private string _propertyName;
        public string PropertyName
        {
            get
            {
                return _propertyName;
            }
        }
    }
}
