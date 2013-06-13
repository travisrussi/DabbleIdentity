using NLog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace Thinktecture.IdentityServer.Web.Controllers
{
    public class ErrorController : Controller
    {
        Logger logger = LogManager.GetCurrentClassLogger();

        //
        // GET: /Error/
        public ActionResult Index(string message)
        {
            ViewBag.Message = message;
            logger.Info(String.Format("Error Information screen called, message = '{0}'", message));
            return View("Error");
        }


        public ActionResult General(Exception exception)
        {
            logger.ErrorException("General Exception Error occurred", exception);
            ViewBag.Exception = exception.Message;
            return View("Error500");
        }

        public ActionResult Http404()
        {
            return View("Error404");
        }

        public ActionResult Http403()
        {
            return View("Error");
        }

        //
        // GET: /Error/LogJavascriptError
        public void LogJavaScriptError(string message)
        {
            logger.Warn("Javascript Error occurred: " + message);
        }

        public ActionResult Test()
        {
            ViewBag.Message = "Test Javascript error logging.";
            return View();
        }

        public ActionResult HackerAttack()
        {
            logger.Log(LogLevel.Warn, "Hacker Attack! Source ip = " + Request.UserHostAddress + ", Target = " + Request.RawUrl + ", User Agent = " + Request.Headers.Get("User-Agent"));
            return new RedirectResult("http://www.youtube.com/watch?v=oHg5SJYRHA0");
        }
    }
}
