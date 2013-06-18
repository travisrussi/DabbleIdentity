/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using Thinktecture.IdentityServer.DataAnnotationExtention;

namespace Thinktecture.IdentityServer.Models
{
    public class IdentityProvider : IValidatableObject
    {
        [UIHint("HiddenInput")]
        public int ID { get; set; }

        [Required]
        [Display(Order = 1, ResourceType = typeof(Resources.Models.IdentityProvider), Name = "Name", Description = "NameDescription")]
        public string Name { get; set; }

        [Required]
        [Display(Order = 2, ResourceType = typeof(Resources.Models.IdentityProvider), Name = "DisplayName", Description = "DisplayNameDescription")]
        public string DisplayName { get; set; }

        [Display(Order = 3, ResourceType = typeof(Resources.Models.IdentityProvider), Name = "Enabled", Description = "EnabledDescription")]
        public bool Enabled { get; set; }

        [Display(Order = 4, ResourceType = typeof(Resources.Models.IdentityProvider), Name = "ShowInHrdSelection", Description = "ShowInHrdSelectionDescription")]
        public bool ShowInHrdSelection { get; set; }

        [Required]
        [UIHint("Enum")]
        [Display(Order = 5, ResourceType = typeof(Resources.Models.IdentityProvider), Name = "Type", Description = "TypeDescription")]
        public Models.IdentityProviderTypes? Type { get; set; }


        [Display(Order = 6, ResourceType = typeof(Resources.Models.IdentityProvider), Name = "WSFederationEndpoint", Description = "WSFederationEndpointDescription")]
        [AbsoluteUri]
        [HtmlDivClassPropertiesAttribute(divClass = "wsFed")]
        public string WSFederationEndpoint { get; set; }

        string _IssuerThumbprint;
        [UIHint("Thumbprint")]
        [HtmlDivClassPropertiesAttribute(divClass = "wsFed")]
        [Display(Order = 7, ResourceType = typeof(Resources.Models.IdentityProvider), Name = "IssuerThumbprint", Description = "IssuerThumbprintDescription")]
        public string IssuerThumbprint
        {
            get
            {
                return _IssuerThumbprint;
            }
            set
            {
                _IssuerThumbprint = value;
                if (_IssuerThumbprint != null) _IssuerThumbprint = _IssuerThumbprint.Replace(" ", "");
            }
        }

        [Display(Order = 8, ResourceType = typeof(Resources.Models.IdentityProvider), Name = "ProviderType")]
        [UIHint("Enum")]
        [HtmlDivClassPropertiesAttribute(divClass = "oauth2")]
        public OAuth2ProviderTypes? OAuth2ProviderType { get; set; }


        [Display(Order = 9, ResourceType = typeof (Resources.Models.IdentityProvider), Name = "ClientID")]
        [HtmlDivClassPropertiesAttribute(divClass = "oauth2")]
        public string ClientID { get; set; }

        [Display(Order = 10, ResourceType = typeof (Resources.Models.IdentityProvider), Name = "ClientSecret")]
        [HtmlDivClassPropertiesAttribute(divClass = "oauth2")]
        public string ClientSecret { get; set; }

        //TODO extend scope for all identity providers
        [Display(Order = 11, ResourceType = typeof(Resources.Models.IdentityProvider), Name = "Scope")]
        [HtmlDivClassPropertiesAttribute(divClass = "oauth2")]
        public string Scope { get; set; }

        [Display(Order = 12, ResourceType = typeof(Resources.Models.IdentityProvider), Name = "OpenIdProvider")]
        [UIHint("Enum")]
        [HtmlDivClassPropertiesAttribute(divClass = "openId")]
        public OpenIdProviderTypes? OpenIdProviderType { get; set; }

        public System.Collections.Generic.IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            List<ValidationResult> errors = new List<ValidationResult>();

            if (this.Type == IdentityProviderTypes.WSStar)
            {
                if (String.IsNullOrEmpty(this.WSFederationEndpoint))
                {
                    errors.Add(new ValidationResult(Resources.Models.IdentityProvider.WSFederationEndpointRequiredError, new string[] { "WSFederationEndpoint" }));
                }
                if (String.IsNullOrEmpty(this.IssuerThumbprint))
                {
                    errors.Add(new ValidationResult(Resources.Models.IdentityProvider.IssuerThumbprintRequiredError, new string[] { "IssuerThumbprint" }));
                }
            }
            if (this.Type == IdentityProviderTypes.OAuth2)
            {
                if (String.IsNullOrEmpty(this.ClientID))
                {
                    errors.Add(new ValidationResult(Resources.Models.IdentityProvider.ClientIDRequiredError, new string[] { "ClientID" }));
                }
                if (String.IsNullOrEmpty(this.ClientSecret))
                {
                    errors.Add(new ValidationResult(Resources.Models.IdentityProvider.ClientSecretRequiredError, new string[] { "ClientSecret" }));
                }
                if (this.OAuth2ProviderType == null)
                {
                    errors.Add(new ValidationResult(Resources.Models.IdentityProvider.ProviderTypeRequiredError, new string[] { "ProfileType" }));
                }
            }
            if (this.Type == IdentityProviderTypes.OpenId)
            {
                if (this.OpenIdProviderType == null)
                {
                    //TODO Implement language setting
                    errors.Add(new ValidationResult("OpenId Provider Type is required.", new string[] { "ProfileType" }));
                }
            }

            return errors;
        }
    }
}