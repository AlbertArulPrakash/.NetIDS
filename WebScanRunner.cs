using System;
using System.Collections.Generic;
using System.Text;
using System.Reflection;
using System.Xml;
using System.Web;
using System.Web.UI;


namespace DOTNETIDS
{
    class WebScanRunner:IScanRunner
    {
        private IDSGlobalSettings _settings = new IDSGlobalSettings();
        private IDSEvent OnIDSEvents;
        private DOTNETIDS.OutputFilter _oF = null;
        private string _pageHTML = string.Empty;
        private bool _callScan = true;

        public string PageHTML
        {
            get { return _pageHTML; }
            set { _pageHTML = value; }
        }

        public WebScanRunner(IDSGlobalSettings settings)
        {
            _settings = settings;
        }

        private void _oF_OnPageReady(DOTNETIDS.OutputFilter oF)
        {
            _pageHTML = oF.Output;
            if (OnIDSEvents != null) OnIDSEvents(oF.Report, this);
        }

        private void RunScan()
        {
            //Determine if we already have a Page Settings object
            IDSPageSettings ips;

            _settings.PageSettings.TryGetValue(Misc.GetCurrentPageName(), out ips);

            if (ips == null)
            {
                ips = new IDSPageSettings(_settings);
                _settings.PageSettings.Add(Misc.GetCurrentPageName(), ips);
            }

            RunScan(ips);
        }
        
        private void RunScan(IDSPageSettings ips)
        {
            HttpRequest Request = HttpContext.Current.Request;
            HttpResponse Response = HttpContext.Current.Response;

            //Perform scanning
            //Add some default exclusions
            if (HttpContext.Current.Request.Url.Host == "localhost")
            {
                _settings.HeaderExclusions.Add("Host");
            }

            //Hook the output
            if (ips.ScanOutput)
            {
                /*_oF = new DOTNETIDS.OutputFilter(Response.Filter, null, System.Text.Encoding.ASCII, _settings.OutputFilterXmlPath);
                _oF.OnPageReady += new DOTNETIDS.OutputFilter.PageReadyEvent(_oF_OnPageReady);
                _oF.JSDecode = _settings.DecodeJS;
                _oF.UTF7Decode = _settings.DecodeUTF7;
                Response.Filter = _oF;*/
            }

            //Pass GET, POST, COOKIES and HEADERS through the IDS
            DOTNETIDS.IDS ids_get;

            if (_settings.FilterXmlPath != string.Empty)
            {
                //Load from file
                ids_get = new DOTNETIDS.IDS(Request.QueryString, _settings.FilterXmlPath);
            }
            else
            {
                //Load from embedded resource
                ids_get = new DOTNETIDS.IDS(Request.QueryString);
            }
            
            DOTNETIDS.IDS ids_post = new DOTNETIDS.IDS(Request.Form, ids_get, DOTNETIDS.RequestType.Post);
            DOTNETIDS.IDS ids_cookies = new DOTNETIDS.IDS(Request.Cookies, ids_get);
            DOTNETIDS.IDS ids_headers = new DOTNETIDS.IDS(Request.Headers, ids_get, DOTNETIDS.RequestType.Header);

            ips.GetExclusions.AddRange(ips.Exclusions);
            ips.PostExclusions.AddRange(ips.Exclusions);
            ips.CookieExclusions.AddRange(ips.Exclusions);
            ips.HeaderExclusions.AddRange(ips.Exclusions);
            
            ips.GetExclusions.AddRange(_settings.Exclusions);
            ips.PostExclusions.AddRange(_settings.Exclusions);
            ips.CookieExclusions.AddRange(_settings.Exclusions);
            ips.HeaderExclusions.AddRange(_settings.Exclusions);
            
            ips.GetExclusions.AddRange(_settings.GetExclusions);
            ips.HeaderExclusions.AddRange(_settings.HeaderExclusions);
            ips.PostExclusions.AddRange(_settings.PostExclusions);
            ips.CookieExclusions.AddRange(_settings.CookieExclusions);

            ids_get.Exclusions.AddRange(ips.GetExclusions);
            ids_post.Exclusions.AddRange(ips.PostExclusions);
            ids_cookies.Exclusions.AddRange(ips.CookieExclusions);
            ids_headers.Exclusions.AddRange(ips.HeaderExclusions);

            ids_get.JSDecode = ips.DecodeJS;
            ids_post.JSDecode = ips.DecodeJS;
            ids_cookies.JSDecode = ips.DecodeJS;
            ids_headers.JSDecode = ips.DecodeJS;

            ids_get.UTF7Decode = ips.DecodeUTF7;
            ids_post.UTF7Decode = ips.DecodeUTF7;
            ids_cookies.UTF7Decode = ips.DecodeUTF7;
            ids_headers.UTF7Decode = ips.DecodeUTF7;


            //Run the IDS on each component
            if (ips.ScanGet)
            {
                ids_get.Run();
                if (OnIDSEvents != null) OnIDSEvents(ids_get.Report, this);
            }

            if (ips.ScanPost)
            {
                ids_post.Run();
                if (OnIDSEvents != null) OnIDSEvents(ids_post.Report, this);
            }

            if (ips.ScanCookies)
            {
                ids_cookies.Run();
                if (OnIDSEvents != null) OnIDSEvents(ids_cookies.Report, this);
            }

            if (ips.ScanHeaders)
            {
                ids_headers.Run();
                if (OnIDSEvents != null) OnIDSEvents(ids_headers.Report, this);
            }
        }

        public void Run()
        {
            //Determine if we already have a Page Settings object
            IDSPageSettings ips;

            _settings.PageSettings.TryGetValue(Misc.GetCurrentPageName(), out ips);

            if (ips == null)
            {
                ips = new IDSPageSettings(_settings);
                _settings.PageSettings.Add(Misc.GetCurrentPageName(), ips);
            }

            //Wire up the web.config page callbacks
            foreach (IDSCallback callback in ips.Callbacks)
            {
                Type t = Misc.ResolveType(callback.Assembly, callback.Namespaceandcallback);
                SetupBinding(t, callback.Method);
            }
            
            if (ips.OnIDSEvent != null)
            {
                foreach (Delegate d in ips.OnIDSEvent.GetInvocationList())
                {
                    OnIDSEvents += (IDSEvent)d;
                }
            }

            //Wire up the web.config global callbacks
            foreach (IDSCallback callback in _settings.Callbacks)
            {
                Type t = Misc.ResolveType(callback.Assembly, callback.Namespaceandcallback);
                SetupBinding(t, callback.Method);
            }

            //If _callScan is false then the firing mechanism will run in
            //the page_preinit event of a page/page subclass
            if (!_callScan) return;

            RunScan(ips);
        }

        private void SetupBinding(Type t, string method)
        {
            MethodInfo mi = t.GetMethod(method);

            //Determine the binding method
            if (mi.IsStatic)
            {
                Delegate d = Delegate.CreateDelegate(typeof(IDSEvent), mi);
                OnIDSEvents += (IDSEvent)d;
            }
            else
            {
                if (t.IsSubclassOf(typeof(Page)))
                {
                    //Set up a callback to an instance method inside a Page
                    object o = HttpContext.Current.CurrentHandler;

                    //Determine if the current Handler is of a usable type
                    if (t.IsInstanceOfType(o))
                    {
                        if (_callScan == true)
                        {
                            ((Page)o).PreInit += new EventHandler(WebScanRunner_PreInit);
                        }

                        Delegate d = Delegate.CreateDelegate(typeof(IDSEvent), o, method);
                        OnIDSEvents += (IDSEvent)d;
                        
                        _callScan = false;
                    }
                }
                else
                {
                    //Set up a callback to an instance method not inside a Page
                    object o = Activator.CreateInstance(t);
                    Delegate d = Delegate.CreateDelegate(typeof(IDSEvent), o, method);
                    OnIDSEvents += (IDSEvent)d;
                }

            }
        }

        private void WebScanRunner_PreInit(object sender, EventArgs e)
        {
            RunScan();
        }

        #region IScanRunner Members

        /// <summary>
        /// Write the original response to the page
        /// </summary>
        public void WriteResponse()
        {
            if (_oF != null) _oF.WriteResponse();
        }

        /// <summary>
        /// Write a new response to the page
        /// </summary>
        /// <param name="AlternativeOutput">The document to write instead of the original</param>
        public void WriteResponse(string AlternativeOutput)
        {
            if (_oF != null) _oF.WriteResponse(AlternativeOutput);
        }

        #endregion
    }
}
