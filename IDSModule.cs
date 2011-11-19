using System;
using System.Collections.Generic;
using System.Text;
using System.Web;
using System.Configuration;
using System.Text.RegularExpressions;

namespace DOTNETIDS
{
    class IDSModule : IHttpModule
    {
        #region IHttpModule Members

        public void Dispose()
        {
            
        }

        public void Init(HttpApplication context)
        {
            //Hook the BeginRequest event
            //context.BeginRequest += new EventHandler(ids_BeginRequest);
            context.PreRequestHandlerExecute += new EventHandler(ids_BeginRequest);
        }

        void ids_BeginRequest(object sender, EventArgs e)
        {
            //Attempt to read the app's config
            IDSGlobalSettings ims = (IDSGlobalSettings)ConfigurationSettings.GetConfig("dotnetids/idsconfig");

            string filename = System.IO.Path.GetFileName(HttpContext.Current.Request.Url.AbsolutePath).ToLowerInvariant();

            //Look for regex options to exclude
            foreach (RegexSettings rs in ims.ExcludedRegexen)
            {
                RegexOptions ro = new RegexOptions();

                if (rs.IgnoreCase)
                {
                    ro = ro | RegexOptions.IgnoreCase;
                }
                
                if (Regex.IsMatch(HttpContext.Current.Request.Url.AbsolutePath, rs.Pattern, ro)) return;
            }

            //Look for pages to exclude
            foreach (string s in ims.ExcludedPages)
            {
                if (s.ToLowerInvariant() == filename) return;
            }

            //Run the scanner
            WebScanRunner sr = new WebScanRunner(ims);
            sr.Run();
        }

        #endregion
    }
}
