using System;
using System.Globalization;
using System.Web;
using System.Web.Hosting;
using Elmah;
using NLog;
using NLog.Targets;
using SqlFu;
using System.Configuration;
using CavemanTools;


//TODO need a webconfig configuration handller
namespace Thinktecture.IdentityServer.Web.Utility
{
    [Target("ElmahTarget")]
    public sealed class ElmahTarget : TargetWithLayout
    {
        protected override void Write(LogEventInfo logEvent)
        {
            try
            {
                if (HttpContext.Current != null && logEvent.Exception != null)
                {
                    ErrorSignal.FromCurrentContext().Raise(logEvent.Exception);
                }
                else
                {
                    // ErrorSignal.FromContext(HttpContext.Current).Raise(new System.ApplicationException(

                    // log directly to sql database
                    using (var dbAccess = new DbAccess(ConfigurationManager.ConnectionStrings["elmahsqlserver"].ConnectionString, DbEngine.SqlServer))
                    {
                        string cmd = @"exec ELMAH_LogError @ErrorId, @Application, @Host, @Type, @Source, @Message, @User, @AllXml, @StatusCode, @TimeUtc";
                        string message;
                        string source;
                        string detail;

                        if (logEvent.Exception != null)
                        {
                            message = logEvent.Exception.Message;
                            source = logEvent.Exception.Source;
                            detail = logEvent.Exception.ToString();
                        }
                        else
                        {
                            message = logEvent.FormattedMessage;
                            source = logEvent.LoggerName;
                            if (logEvent.StackTrace != null)
                                detail = logEvent.StackTrace.ToString();
                            else
                                detail = "(no error details available)";
                        }

                        dbAccess.ExecuteCommand(cmd,
                            new
                            {
                                ErrorId = Guid.NewGuid(),
                                Application = HostingEnvironment.ApplicationID,
                                Host = Environment.MachineName,
                                Type = logEvent.Level.Name,
                                Source = logEvent.LoggerName,
                                Message = logEvent.FormattedMessage,
                                User = System.Security.Principal.WindowsIdentity.GetCurrent().Name.ToString(),
                                AllXml = "<error application=\"" + HostingEnvironment.ApplicationID +
                                    "\"  message=\"" + HttpUtility.HtmlEncode(message) +
                                    "\" source=\"" + HttpUtility.HtmlEncode(source) +
                                    "\" detail=\"" + HttpUtility.HtmlEncode(detail) +
                                    "\" time=\"" + DateTime.Now.ToString("s") + "\"  ></error>",
                                StatusCode = 0,
                                TimeUtc = DateTime.UtcNow
                            });

                        //Cleans old logs
                        dbAccess.ExecuteCommand("DELETE FROM ELMAH_Error Where TimeUtc <= @Time", new { Time = DateTime.UtcNow.Subtract(TimeSpan.FromDays(14)) });
                    }
                }
            }
            catch (Exception)
            {
                // in the error log, we can't do much else that fail silently
            }
        }
    }
}