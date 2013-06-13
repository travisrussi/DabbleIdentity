using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace Thinktecture.IdentityServer.DataAnnotationExtention
{
    public class MetadataProvider : DataAnnotationsModelMetadataProvider
    {
        protected override ModelMetadata CreateMetadata(IEnumerable<Attribute> attributes,
                                                        Type containerType, Func<object> modelAccessor, Type modelType, string propertyName)
        {
            var metadata = base.CreateMetadata(attributes, containerType, modelAccessor, modelType, propertyName);
            var additionalValues = attributes.OfType<HtmlDivClassPropertiesAttribute>().FirstOrDefault();
            if (additionalValues != null)
            {
                metadata.AdditionalValues.Add("DivClass", additionalValues);
            }
            return metadata;
        }
    }
    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
    public class HtmlDivClassPropertiesAttribute : Attribute
    {
        public string divClass
        {
            get;
            set;
        }

        //public IDictionary<string, object> HtmlDivClassProperties()
        //{
        //    //Todo: we could use TypeDescriptor to get the dictionary of properties and their values
        //    IDictionary<string, object> htmlDCP = new Dictionary<string, object>();
        //    if (!string.IsNullOrEmpty(divClass))
        //    {
        //        htmlDCP.Add("divClass", divClass);
        //    }
        //    return htmlDCP;
        //}
    }
}