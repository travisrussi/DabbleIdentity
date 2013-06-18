using System.Web.Optimization;

namespace Thinktecture.IdentityServer.Web
{
    public class BundleConfig
    {
        public static void RegisterBundles(BundleCollection bundles)
        {
            bundles.Add(new ScriptBundle("~/bundles/js/jquery").Include(
                        "~/Scripts/jquery-{version}.js"));

            bundles.Add(new ScriptBundle("~/bundles/js/jqueryui").Include(
                        "~/Scripts/jquery-ui-{version}.js"));
            bundles.Add(new ScriptBundle("~/bundles/js/jqueryval").Include(
                        "~/Scripts/jquery.unobtrusive*",
                        "~/Scripts/jquery.validate*"));

            bundles.Add(new ScriptBundle("~/bundles/js/modernizr").Include(
                        "~/Scripts/modernizr-{version}.js"));

            bundles.Add(new StyleBundle("~/bundles/css/openid").Include(
                "~/Content/openid/openid.css"
                ));

            bundles.Add(new ScriptBundle("~/bundles/js/plugins").Include(
                "~/Scripts/hints.js",
                "~/Scripts/bootstrap-collapse.js",
                "~/Scripts/bootstrap-alert.js",
                "~/Scripts/jquery.h5validate.js",
                "~/Scripts/validate.js",
                "~/Scripts/submitbutton.js",
                "~/Scripts/address.js"));


            /*bundles.Add(new StyleBundle("~/bundles/css/themes/base").Include(
                                    "~/Content/themes/base/jquery.ui.core.css",
                                    "~/Content/themes/base/jquery.ui.resizable.css",
                                    "~/Content/themes/base/jquery.ui.selectable.css",
                                    "~/Content/themes/base/jquery.ui.accordion.css",
                                    "~/Content/themes/base/jquery.ui.autocomplete.css",
                                    "~/Content/themes/base/jquery.ui.button.css",
                                    "~/Content/themes/base/jquery.ui.dialog.css",
                                    "~/Content/themes/base/jquery.ui.slider.css",
                                    "~/Content/themes/base/jquery.ui.tabs.css",
                                    "~/Content/themes/base/jquery.ui.datepicker.css",
                                    "~/Content/themes/base/jquery.ui.progressbar.css",
                                    "~/Content/themes/base/jquery.ui.theme.css"));
                         * */
        }
    }
}