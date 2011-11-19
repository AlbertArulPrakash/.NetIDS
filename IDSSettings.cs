using System;
using System.Collections.Generic;
using System.Text;
using System.Configuration;
using System.Reflection;
using System.Xml;
using System.Web;
using System.Web.UI;

namespace DOTNETIDS
{
    /// <summary>
    /// A Config Handler for the IDS
    /// </summary>
    public class IDSConfigHandler : IConfigurationSectionHandler
    {
        public IDSConfigHandler() { }

        public object Create(object parent,
               object configContext, System.Xml.XmlNode section)
        {
            IDSGlobalSettings settings = new IDSGlobalSettings();
            IDSBaseSettings ibs = (IDSBaseSettings)settings;

            //Load base IDS settings
            LoadBaseSettings(ref ibs, section);

            //Get page exclusions
            XmlNodeList xnl = section.SelectNodes("excludepage");

            foreach (XmlNode n in xnl)
            {
                string pagetoexclude = GetAttribute(n, "page", true);
                settings.ExcludedPages.Add(pagetoexclude);
            }

            //Get regex exclusions
            xnl = section.SelectNodes("excluderegex");

            foreach (XmlNode n in xnl)
            {
                string pattern = GetAttribute(n, "pattern", true);
                bool ignorecase = bool.Parse(GetAttribute(n, "ignorecase", true));
                settings.ExcludedRegexen.Add(new RegexSettings(pattern, ignorecase));
            }
            
            //Get the global callbacks
            xnl = section.SelectNodes("callback");

            foreach (XmlNode n in xnl)
            {
                string method = GetAttribute(n, "method", true);
                string namespaceandtype = GetAttribute(n, "namespaceandtype", true);
                string assembly = GetAttribute(n, "assembly", true);

                settings.Callbacks.Add(new IDSCallback(method, namespaceandtype, assembly));
            }

            //Get page settings
            xnl = section.SelectNodes("pagesetup");

            foreach (XmlNode n in xnl)
            {
                string pagename = GetAttribute(n, "page", true);

                //Create a page settings object
                IDSPageSettings ips = new IDSPageSettings(settings);

                try
                {
                    settings.PageSettings.Add(pagename, ips);
                }
                catch (Exception e)
                {
                    throw new ApplicationException("Only one config section can exist for the page named \"" + pagename + "\"", e);
                }

                //Populate base data
                IDSBaseSettings pagebase = (IDSBaseSettings)ips;
                LoadBaseSettings(ref pagebase, n);

                //Look for page callbacks
                XmlNodeList pagecallbacks = n.SelectNodes("callback");

                foreach (XmlNode pagecallback in pagecallbacks)
                {
                    string method = GetAttribute(pagecallback, "method", true);
                    string namespaceandtype = GetAttribute(pagecallback, "namespaceandtype", true);
                    string assembly = GetAttribute(pagecallback, "assembly", true);

                    ips.Callbacks.Add(new IDSCallback(method, namespaceandtype, assembly));
                }
            }
            
            return settings;
        }

        private void LoadBaseSettings(ref IDSBaseSettings settings, XmlNode xn)
        {
            //Cookie exclusions
            XmlNodeList configoption = xn.SelectNodes("cookieexclusion");
            
            foreach (XmlNode cookieexclusion in configoption)
            {
                settings.CookieExclusions.Add(GetAttribute(cookieexclusion, "name", true));
            }
            
            //DecodeJS
            configoption = xn.SelectNodes("decodejs");

            if (configoption.Count > 0)
            {
                bool decodejs = true;

                if (!bool.TryParse(GetAttribute(configoption[0], "value", true), out decodejs))
                {
                    throw new ApplicationException("The value parameter of \"decodejs\" must be either \"true\" or \"false\".");
                }

                settings.DecodeJS = decodejs;
            }

            //DecodeUTF7
            configoption = xn.SelectNodes("decodeutf7");

            if (configoption.Count > 0)
            {
                bool decodeutf7 = true;

                if (!bool.TryParse(GetAttribute(configoption[0], "value", true), out decodeutf7))
                {
                    throw new ApplicationException("The value parameter of \"decodeutf7\" must be either \"true\" or \"false\".");
                }

                settings.DecodeUTF7 = decodeutf7;
            }

            //Exclusions
            configoption = xn.SelectNodes("exclusion");

            foreach (XmlNode exclusion in configoption)
            {
                settings.Exclusions.Add(GetAttribute(exclusion, "name", true));
            }

            //Get Exclusions
            configoption = xn.SelectNodes("getexclusion");

            foreach (XmlNode getexclusion in configoption)
            {
                settings.GetExclusions.Add(GetAttribute(getexclusion, "name", true));
            }

            //Header Exclusions
            configoption = xn.SelectNodes("headerexclusion");

            foreach (XmlNode headerexclusion in configoption)
            {
                settings.HeaderExclusions.Add(GetAttribute(headerexclusion, "name", true));
            }

            //Header Exclusions
            configoption = xn.SelectNodes("postexclusion");

            foreach (XmlNode postexclusion in configoption)
            {
                settings.PostExclusions.Add(GetAttribute(postexclusion, "name", true));
            }

            //Scan cookies
            configoption = xn.SelectNodes("scancookies");

            if (configoption.Count > 0)
            {
                bool scancookies = true;

                if (!bool.TryParse(GetAttribute(configoption[0], "value", true), out scancookies))
                {
                    throw new ApplicationException("The value parameter of \"scancookies\" must be either \"true\" or \"false\".");
                }

                settings.ScanCookies = scancookies;
            }

            //Scan get
            configoption = xn.SelectNodes("scanget");

            if (configoption.Count > 0)
            {
                bool scanget = true;

                if (!bool.TryParse(GetAttribute(configoption[0], "value", true), out scanget))
                {
                    throw new ApplicationException("The value parameter of \"scanget\" must be either \"true\" or \"false\".");
                }

                settings.ScanGet = scanget;
            }

            //Scan headers
            configoption = xn.SelectNodes("scanheaders");

            if (configoption.Count > 0)
            {
                bool scanheaders = true;

                if (!bool.TryParse(GetAttribute(configoption[0], "value", true), out scanheaders))
                {
                    throw new ApplicationException("The value parameter of \"scanheaders\" must be either \"true\" or \"false\".");
                }

                settings.ScanHeaders = scanheaders;
            }

            //Scan keys
            configoption = xn.SelectNodes("scankeys");

            if (configoption.Count > 0)
            {
                bool scankeys = true;

                if (!bool.TryParse(GetAttribute(configoption[0], "value", true), out scankeys))
                {
                    throw new ApplicationException("The value parameter of \"scankeys\" must be either \"true\" or \"false\".");
                }

                settings.ScanKeys = scankeys;
            }

            //Scan output
            configoption = xn.SelectNodes("scanoutput");

            if (configoption.Count > 0)
            {
                bool scanoutput = true;

                if (!bool.TryParse(GetAttribute(configoption[0], "value", true), out scanoutput))
                {
                    throw new ApplicationException("The value parameter of \"scanoutput\" must be either \"true\" or \"false\".");
                }

                settings.ScanOutput = scanoutput;
            }

            //Scan post
            configoption = xn.SelectNodes("scanpost");

            if (configoption.Count > 0)
            {
                bool scanpost = true;

                if (!bool.TryParse(GetAttribute(configoption[0], "value", true), out scanpost))
                {
                    throw new ApplicationException("The value parameter of \"scanpost\" must be either \"true\" or \"false\".");
                }

                settings.ScanPost = scanpost;
            }
        }

        internal string GetAttribute(XmlNode n, string attributeName, bool throwIfNotFound)
        {
            XmlAttribute at = n.Attributes[attributeName];
            
            if (at == null)
            {
                if (throwIfNotFound)
                {
                    throw new ApplicationException("\"" + attributeName + "\" must be specified for each \"" + n.Name + "\" provided.");
                }
                else
                {
                    return string.Empty;
                }
            }

            return at.InnerText;
        }
       
    }

    /// <summary>
    /// The options available for each page
    /// </summary>
    public class IDSPageSettings : IDSBaseSettings
    {
        public IDSEvent OnIDSEvent;

        private List<IDSCallback> _callbacks = new List<IDSCallback>();

        internal List<IDSCallback> Callbacks
        {
            get { return _callbacks; }
            set { _callbacks = value; }
        }

        public IDSPageSettings(IDSGlobalSettings GlobalSettings)
        {
            this.CookieExclusions.AddRange(GlobalSettings.CookieExclusions);
            this.DecodeJS = GlobalSettings.DecodeJS;
            this.DecodeUTF7 = GlobalSettings.DecodeUTF7;
            this.ScanCookies = GlobalSettings.ScanCookies;
            this.ScanGet = GlobalSettings.ScanGet;
            this.ScanHeaders = GlobalSettings.ScanHeaders;
            this.ScanKeys = GlobalSettings.ScanKeys;
            this.ScanOutput = GlobalSettings.ScanOutput;
            this.ScanPost = GlobalSettings.ScanPost;
        }
    }

    /// <summary>
    /// Stores textual information about a callback
    /// </summary>
    public class IDSCallback
    {
        private string _method = string.Empty;

        public string Method
        {
            get { return _method; }
            set { _method = value; }
        }
        private string _namespaceandcallback = string.Empty;

        public string Namespaceandcallback
        {
            get { return _namespaceandcallback; }
            set { _namespaceandcallback = value; }
        }
        private string _assembly = string.Empty;

        public string Assembly
        {
            get { return _assembly; }
            set { _assembly = value; }
        }

        public IDSCallback(string method, string namespaceandtype, string assembly)
        {
            _method = method;
            _namespaceandcallback = namespaceandtype;
            _assembly = assembly;
        }
    }

    public class IDSBaseSettings
    {
        private bool _decodeJS = true;
        private bool _decodeUTF7 = true;
        private bool _scanOutput = true;
        private bool _scanCookies = true;
        private bool _scanHeader = true;
        private bool _scanGet = true;
        private bool _scanPost = true;
        private bool _scanKeys = true;
        
        private List<string> _exclusions_cookies = new List<string>();
        private List<string> _exclusions_get = new List<string>();
        private List<string> _exclusions_post = new List<string>();
        private List<string> _exclusions_headers = new List<string>();
        private List<string> _exclusions = new List<string>();

        /// <summary>
        /// Whether to scan keys as well as values
        /// </summary>
        public bool ScanKeys
        {
            get { return _scanKeys; }
            set { _scanKeys = value; }
        }

        /// <summary>
        /// Whether to perform output scanning
        /// </summary>
        public bool ScanOutput
        {
            get { return _scanOutput; }
            set { _scanOutput = value; }
        }

        /// <summary>
        /// Whether to perform querystring scanning
        /// </summary>
        public bool ScanGet
        {
            get { return _scanGet; }
            set { _scanGet = value; }
        }

        /// <summary>
        /// Whether to perform POST scanning
        /// </summary>
        public bool ScanPost
        {
            get { return _scanPost; }
            set { _scanPost = value; }
        }

        /// <summary>
        /// Whether to perform cookie scanning
        /// </summary>
        public bool ScanCookies
        {
            get { return _scanCookies; }
            set { _scanCookies = value; }
        }

        /// <summary>
        /// Whether to perform header scanning
        /// </summary>
        public bool ScanHeaders
        {
            get { return _scanHeader; }
            set { _scanHeader = value; }
        }

        /// <summary>
        /// Whether or not to decode JavaScript fromCharCode() style encodings
        /// </summary>
        public bool DecodeJS
        {
            get { return _decodeJS; }
            set { _decodeJS = value; }
        }

        /// <summary>
        /// Whether or not to decode UTF7 Ascii representations
        /// </summary>
        public bool DecodeUTF7
        {
            get { return _decodeUTF7; }
            set { _decodeUTF7 = value; }
        }

        /// <summary>
        /// A list of additional Exclusions that will not be scanned
        /// </summary>
        public System.Collections.Generic.List<string> Exclusions
        {
            get { return _exclusions; }
            set { _exclusions = value; }
        }

        /// <summary>
        /// Cookies to exclude from scanning
        /// </summary>
        public System.Collections.Generic.List<string> CookieExclusions
        {
            get { return _exclusions_cookies; }
            set { _exclusions_cookies = value; }
        }

        /// <summary>
        /// Querystrings to exclude from scanning
        /// </summary>
        public System.Collections.Generic.List<string> GetExclusions
        {
            get { return _exclusions_get; }
            set { _exclusions_get = value; }
        }

        /// <summary>
        /// POST fields to exclude from scanning
        /// </summary>
        public System.Collections.Generic.List<string> PostExclusions
        {
            get { return _exclusions_post; }
            set { _exclusions_post = value; }
        }

        /// <summary>
        /// Headers to exclude from scanning
        /// </summary>
        public System.Collections.Generic.List<string> HeaderExclusions
        {
            get { return _exclusions_headers; }
            set { _exclusions_headers = value; }
        }
    }

    public class RegexSettings
    {
        string _pattern = string.Empty;

        public string Pattern
        {
            get { return _pattern; }
            set { _pattern = value; }
        }
        bool _ignorecase = false;

        public bool IgnoreCase
        {
            get { return _ignorecase; }
            set { _ignorecase = value; }
        }

        public RegexSettings(string pattern, bool ignorecase)
        {
            _pattern = pattern;
            _ignorecase = ignorecase;
        }
    }

    /// <summary>
    /// The options available for web applications using .NETIDS
    /// </summary>
    public class IDSGlobalSettings: IDSBaseSettings
    {
        private Dictionary<string, IDSPageSettings> _pageSettings = new Dictionary<string, IDSPageSettings>();
        private List<IDSCallback> _callbacks = new List<IDSCallback>();
        private List<String> _excludedpages = new List<string>();
        private List<RegexSettings> _excludedregexen = new List<RegexSettings>();
        
        private string _filterXmlPath = string.Empty;
        private string _pageHTML = string.Empty;
        private bool _callScan = true;

        public Dictionary<string, IDSPageSettings> PageSettings
        {
            get { return _pageSettings; }
            set { _pageSettings = value; }
        }

        internal bool CallScan
        {
            get { return _callScan; }
            set { _callScan = value; }
        }

        internal List<IDSCallback> Callbacks
        {
            get { return _callbacks; }
            set { _callbacks = value; }
        }

        public List<String> ExcludedPages
        {
            get { return _excludedpages; }
            set { _excludedpages = value; }
        }

        public List<RegexSettings> ExcludedRegexen
        {
            get { return _excludedregexen; }
            set { _excludedregexen = value; }
        }


        #region Properties
        /// <summary>
        /// The path to the Default Filter file
        /// </summary>
        public string FilterXmlPath
        {
            get { return _filterXmlPath; }
            set { _filterXmlPath = value; }
        }
        #endregion
    }
}
