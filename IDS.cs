/*
    * .NET IDS
    * A port of PHP IDS to the .NET Framework
    * 
    * Requirements: .NET Framework 2.0/Mono
    * 
    * Copyright (c) 2007 .NETIDS (http://code.google.com/p/dotnetids)
    *
    * This program is free software; you can redistribute it and/or modify
    * it under the terms of the GNU General Public License as published by
    * the Free Software Foundation; version 2 of the license.
    *
    * This program is distributed in the hope that it will be useful,
    * but WITHOUT ANY WARRANTY; without even the implied warranty of
    * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    * GNU General Public License for more details.
*/

/*
    * Intrusion Dectection System
    *
    * This class provides function(s) to scan incoming data for
    * malicious script fragments and to return an array of possibly
    * intrusive parameters.
    *
    * @author   Martin <mhinks@gmail.com>
*/

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Text;
using System.Xml;

namespace DOTNETIDS
{

#region Enums
    /// <summary>
    /// Indicates the type of request
    /// </summary>
    public enum RequestType
    {
        /// <summary>
        /// A GET request
        /// </summary>
        Get,
        /// <summary>
        /// A POST request
        /// </summary>
        Post,
        /// <summary>
        /// A COOKIE request
        /// </summary>
        Cookie,
        /// <summary>
        /// A header
        /// </summary>
        Header,
        /// <summary>
        /// Page output
        /// </summary>
        Output
    }
#endregion

    #region delegates
    /// <summary>
    /// A delegate for IDSEvent
    /// </summary>
    /// <param name="report">A list of IDS reports</param>
    /// <param name="SecurePage">The page that triggered this event</param>
    //public delegate void IDSEvent(DOTNETIDS.Report report, SecurePage SecurePage);

    public delegate void IDSEvent(DOTNETIDS.Report report, IScanRunner Sender);
    #endregion

    /// <summary>
    /// The .NET Intrustion Detection System
    /// </summary>
    /// <example>
    /// <code>
    /// //Create an IDS object
    /// 
    /// DOTNETIDS.IDS ids_get = new DOTNETIDS.IDS(Request.QueryString, Server.MapPath("~/IDS/default_filter.xml"));
    /// 
    /// //Run the IDS
    /// 
    /// ids_get.Run();
    /// 
    /// //Determine if any action is needed
    /// 
    /// if (ids_get.Report.Events.Count > 0)
    /// {
    ///     //Take action
    /// }
    /// </code>
    /// </example>
    public class IDS
    {

        #region Private Fields
        private NameValueCollection _request = null;
        internal Storage _store = null;
        private Report _report = new Report(RequestType.Get);
        private System.Web.HttpCookieCollection _cookies = null;
        private bool _isForm = false;
        private List<string> _exclusions = new List<string>();
        private bool _isCookie = false;
        private bool _nullByteFilter = true;
        private bool _UTF7Dencode = true;
        private bool _JSDencode = true;
        private bool _isRaw = false;
        private string _pageOutput = String.Empty;
        private System.Web.UI.Page _page = null;
        private OutputFilter _oF = null;
        private bool _isHeader = false;
        private bool _scanKeys = true;
        #endregion

        #region Properties

        /// <summary>
        /// Whether to scan keys or not
        /// </summary>
        public bool ScanKeys
        {
            get { return _scanKeys; }
            set { _scanKeys = value; }
        }

        /// <summary>
        /// Whether this is a header request
        /// </summary>
        public bool IsHeader
        {
            get { return _isHeader; }
            set { _isHeader = value; }
        }

        /// <summary>
        /// The page output
        /// </summary>
        internal string PageOutput
        {
            get { return _pageOutput; }
            set { _pageOutput = value; }
        }
        
        /// <summary>
        /// The page this request was based on
        /// </summary>
        internal System.Web.UI.Page Page
        {
            get { return _page; }
            set { _page = value; }
        }

        /// <summary>
        /// Whether this is a raw request
        /// </summary>
        internal bool IsRaw
        {
            get { return _isRaw; }
            set { _isRaw = value; }
        }

        /// <summary>
        /// Whether to decode UTF7 input
        /// </summary>
        public bool UTF7Decode
        {
            get { return _UTF7Dencode; }
            set { _UTF7Dencode = value; }
        }
        
        /// <summary>
        /// Whether to decode JavaScript fromCharCode encoded input
        /// </summary>
        public bool JSDecode
        {
            get { return _JSDencode; }
            set { _JSDencode = value; }
        }

        /// <summary>
        /// Get or set whether the incoming request is a cookie object
        /// </summary>
        public bool IsCookie
        {
            get { return _isCookie; }
            set { _isCookie = value; }
        }

        /// <summary>
        /// Get or set a list of keys to exclude
        /// </summary>
        public List<string> Exclusions
        {
            get { return _exclusions; }
            set { _exclusions = value; }
        }

        /// <summary>
        /// Get or set whether the incoming request is a POST form
        /// </summary>
        public bool IsForm
        {
            get { return _isForm; }
            set { _isForm = value; }
        }

        /// <summary>
        /// The Report generated by the IDS
        /// </summary>
        public Report Report
        {
            get { return _report; }
            set { _report = value; }
        }

        #endregion

        #region Constructors
        /// <summary>
        /// Initialise the IDS to scan output
        /// </summary>
        /// <param name="oF">An OutputFilter</param>
        internal IDS(OutputFilter oF)
        {
            _store = oF._store;
            _pageOutput = oF.Output;
            _page = oF.Page;
            _report = new Report(RequestType.Output);
            _isRaw = true;
            _oF = oF;
        }

        /// <summary>
        /// Initialise the IDS to scan a GET request
        /// </summary>
        /// <param name="request">The Name-Value collection to detect intrusions within</param>
        public IDS(NameValueCollection request)
        {
            XmlDocument xd = new XmlDocument();
            xd.Load(this.GetType().Assembly.GetManifestResourceStream("IDS.default_filter.xml"));
            _store = new Storage(xd, typeof(RegexFilter));
            _request = request;
            _report = new Report(RequestType.Get);
        }

        /// <summary>
        /// Initialise the IDS to scan a GET request
        /// </summary>
        /// <param name="request">The Name-Value collection to detect intrusions within</param>
        /// <param name="xmlPath">The path to the filters file</param>
        public IDS(NameValueCollection request, string xmlPath)
        {
            XmlDocument xd = new XmlDocument();
            xd.Load(xmlPath);
            _store = new Storage(xd, typeof(RegexFilter));
            _request = request;
            _report = new Report(RequestType.Get);
        }

        /// <summary>
        /// Initialise the IDS to scan a GET request using the same filters as an already existing IDS object
        /// </summary>
        /// <param name="request">The Name-Value collection to detect intrusions within</param>
        /// <param name="ids">The IDS containing the preloaded filters</param>
        public IDS(NameValueCollection request, IDS ids)
        {
            _store = ids._store;
            _request = request;
            _report = new Report(RequestType.Get);
        }

        /// <summary>
        /// Initialise the IDS to scan a GET, POST or other request
        /// </summary>
        /// <param name="request">The Name-Value collection to detect intrusions within</param>
        /// <param name="requestType">Indicates What type of request this is and therefore whether to exclude certain parameters.</param>
        public IDS(NameValueCollection request, RequestType requestType)
        {
            XmlDocument xd = new XmlDocument();
            xd.Load(this.GetType().Assembly.GetManifestResourceStream("IDS.default_filter.xml"));
            _store = new Storage(xd, typeof(RegexFilter));
            _request = request;
            _report = new Report(requestType);

            switch (requestType)
            {
                case RequestType.Cookie:
                    IsCookie = true;
                    break;
                case RequestType.Post:
                    IsForm = true;
                    break;
                case RequestType.Header:
                    IsHeader = true;
                    break;
            }

        }

        /// <summary>
        /// Initialise the IDS to scan a GET, POST or other request
        /// </summary>
        /// <param name="request">The Name-Value collection to detect intrusions within</param>
        /// <param name="xmlPath">The path to the filters file</param>
        /// <param name="requestType">Indicates What type of request this is and therefore whether to exclude certain parameters.</param>
        public IDS(NameValueCollection request, string xmlPath, RequestType requestType)
        {
            XmlDocument xd = new XmlDocument();
            xd.Load(xmlPath);
            _store = new Storage(xd, typeof(RegexFilter));
            _request = request;
            _report = new Report(requestType);

            switch (requestType)
            {
                case RequestType.Cookie:
                    IsCookie = true;
                    break;
                case RequestType.Post:
                    IsForm = true;
                    break;
                case RequestType.Header:
                    IsHeader = true;
                    break;
            }
            
        }

        /// <summary>
        /// Initialise the IDS to scan a GET, POST or other request using the same filters as an already existing IDS object
        /// </summary>
        /// <param name="request">The Name-Value collection to detect intrusions within</param>
        /// <param name="ids">The IDS containing the preloaded filters</param>
        /// <param name="requestType">Indicates What type of request this is and therefore whether to exclude certain parameters.</param>
        public IDS(NameValueCollection request, IDS ids, RequestType requestType)
        {
            _store = ids._store;
            _request = request;
            _report = new Report(requestType);

            switch (requestType)
            {
                case RequestType.Cookie:
                    IsCookie = true;
                    break;
                case RequestType.Post:
                    IsForm = true;
                    break;
                case RequestType.Header:
                    IsHeader = true;
                    break;
            }

        }

        /// <summary>
        /// Initialise the IDS to scan cookies using the same filters as an already existing IDS object
        /// </summary>
        /// <param name="cookies">The cookie collection to detect intrusions within</param>
        /// <param name="ids">The IDS containing the preloaded filters</param>
        public IDS(System.Web.HttpCookieCollection cookies, IDS ids)
        {
            _store = ids._store;
            _cookies = cookies;
            _report = new Report(RequestType.Cookie);
            
            IsCookie = true;
        }

        /// <summary>
        /// Initialise the IDS to scan cookies
        /// </summary>
        /// <param name="cookies">The cookie collection to detect intrusions within</param>
        /// <param name="xmlPath">The path to the filters file</param>
        public IDS(System.Web.HttpCookieCollection cookies, string xmlPath)
        {
            XmlDocument xd = new XmlDocument();
            xd.Load(xmlPath);
            _store = new Storage(xd, typeof(RegexFilter));
            _cookies = cookies;
            _report = new Report(RequestType.Cookie);

            IsCookie = true;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Perform intrusion detection
        /// </summary>
        /// <param name="DetectNullBytes">Specify whether to use internal null byte detection</param>
        /// <returns>An intrusion detection report</returns>
        public Report Run(bool DetectNullBytes)
        {
            _nullByteFilter = DetectNullBytes;

            return Run();
        }

        /// <summary>
        /// Perform intrusion detection
        /// </summary>
        /// <returns>An intrusion detection report</returns>
        public Report Run()
        {

            if (_nullByteFilter)
            {
                //Load internal filters
                NullByteFilter nbf = new NullByteFilter();
                _store.AddFilter(nbf);
            }
            

            if (IsForm)
            {
                Exclusions.Add("__VIEWSTATE");
                Exclusions.Add("__EVENTTARGET");
                Exclusions.Add("__EVENTARGUMENT");
                Exclusions.Add("__EVENTVALIDATION");
            }

            if (IsCookie)
            {
                Exclusions.Add(".ASPROLES");
            }

            if (IsHeader)
            {
                Exclusions.Add("Accept");
                Exclusions.Add("Cookie");
                Exclusions.Add("Content-Type");
            }

            if (!IsRaw)
            {
                if (_request != null)
                {
                    //Do POST and GET
                    foreach (string key in _request.Keys)
                    {
                        if (!Exclusions.Contains(key))
                        {
                            string val = _request.Get(key);
                            Iterate(key, val);
                        }
                    }
                }
                else
                {
                    //Process cookies
                    foreach (string key in _cookies.AllKeys)
                    {
                        if (!Exclusions.Contains(key))
                        {
                            string val = _cookies.Get(key).Value;
                            Iterate(key, val);
                        }
                    }
                }
            }
            else
            {
                //Do a raw request (OutputFilter)
                string key = "Page Output";
                string val = ConcatControls();
                
                if (!Exclusions.Contains(key))
                {
                    Iterate(key, val);
                }
            }

            _report.Exclusions = _exclusions;

            return _report;
        }
        #endregion

        #region Private Methods

        /// <summary>
        /// Concacternates the web controls for a raw request
        /// </summary>
        /// <returns>A string of concacternated values</returns>
        private string ConcatControls()
        {
            if (_page == null)
            {
                return "";
            }

            string ret = "";

            ControlRenderInteceptor cri = _oF.GetInterceptor();

            foreach (System.Web.UI.Control formsearch in _page.Controls)
            {
                if (formsearch.GetType().ToString() == "System.Web.UI.HtmlControls.HtmlForm")
                {
                    IterateOver(ref ret, formsearch, cri);
                }

            }

            return ret;
        }

        private void IterateOver(ref string ret, System.Web.UI.Control parent, ControlRenderInteceptor cri)
        {
            foreach (System.Web.UI.Control c in parent.Controls)
            {
                IterateOver(ref ret, c, cri);
                switch (c.GetType().ToString())
                {
                    case "System.Web.UI.WebControls.Literal":
                        c.RenderControl(cri);
                        ret += cri.LastOutput;
                        break;
                }
            }
        }

        /// <summary>
        /// Iterates over a set of keys and values
        /// </summary>
        /// <param name="key">The key</param>
        /// <param name="val">The value</param>
        private void Iterate(string key, string val)
        {
            Event e = new Event(key, val, Detect(key, val));

            if (e.Filters != null && e.Filters.Count > 0)
            {
                _report.AddEvent(e);
            }
        }

        /// <summary>
        /// Calls each Filter's Match method against the specified key and value
        /// </summary>
        /// <param name="key">The key</param>
        /// <param name="val">The value</param>
        /// <returns>A List of Filters that matched the input</returns>
        private List<Filter> Detect(string key, string val)
        {
            if (_exclusions.Contains(key))
            {
                return null;
            }

            if (key == null)
            {
                key = string.Empty;
            }

            if (val == null)
            {
                val = string.Empty;
            }

            //Check if input match a-Z_- for which there is no exploit
            string pattern = "^(\\w+)$";

            if (System.Text.RegularExpressions.Regex.IsMatch(key, pattern) && System.Text.RegularExpressions.Regex.IsMatch(val, pattern))
            {
                //No need to detect further
                return null;
            }

            List<Filter> ret = new List<Filter>();

            //START DECODING

            /* Match PHPIDS' conversion order
            $value = IDS_Converter::convertFromUTF7($value);
            $value = IDS_Converter::convertQuotes($value);
            $value = IDS_Converter::convertFromJSCharcode($value);
            $value = IDS_Converter::convertFromCommented($value);
            $value = IDS_Converter::convertConcatenations($value);
            */

            string keydecoded = key;
            string valdecoded = val;

            //UTF7 Decode
            if (UTF7Decode)
            {
                keydecoded = CharsetConverter.convertFromUTF7(keydecoded);
                valdecoded = CharsetConverter.convertFromUTF7(valdecoded);
            }

            //Quotes Decode
            keydecoded += CharsetConverter.convertQuotes(keydecoded);
            valdecoded += CharsetConverter.convertQuotes(valdecoded);
            
            //JS Decode
            if (JSDecode)
            {
                keydecoded += CharsetConverter.convertFromJSCharcode(keydecoded);
                valdecoded += CharsetConverter.convertFromJSCharcode(valdecoded);
            }

            //Comment decode
            keydecoded += CharsetConverter.convertComments(keydecoded);
            valdecoded += CharsetConverter.convertComments(valdecoded);

            //Concat decode
            keydecoded += CharsetConverter.convertConcats(keydecoded);
            valdecoded += CharsetConverter.convertConcats(valdecoded);

            //Centrifuge decode
            //keydecoded += CharsetConverter.convertCentrifuge(keydecoded);
            //valdecoded += CharsetConverter.convertCentrifuge(valdecoded);

            foreach (Filter f in _store.FilterSet)
            {
                if (f.Match(valdecoded))
                {
                    ret.Add(f);
                }

                if (ScanKeys)
                {
                    if (f.Match(keydecoded))
                    {
                        ret.Add(f);
                    }
                }
            }

            return ret;
        }
        #endregion
    }
}
