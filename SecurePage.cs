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
    * Secure Page
    *
    * This class provides a base class from which you can
    * derive your own Pages to be handled by the IDS
    *
    * @author   Martin <mhinks@gmail.com>
*/

using System;
using System.Data;
using System.Configuration;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Web.UI.HtmlControls;
using System.Globalization;

namespace DOTNETIDS
{
    /// <summary>
    /// A mechanism to secure pages through the IDS
    /// </summary>
    public abstract class SecurePage : System.Web.UI.Page
    {
        #region Private Fields
        private System.Collections.Generic.List<string> _exclusions_cookies = new System.Collections.Generic.List<string>();
        private System.Collections.Generic.List<string> _exclusions_get = new System.Collections.Generic.List<string>();
        private System.Collections.Generic.List<string> _exclusions_post = new System.Collections.Generic.List<string>();
        private System.Collections.Generic.List<string> _exclusions_headers = new System.Collections.Generic.List<string>();
        private System.Collections.Generic.List<string> _exclusions = new System.Collections.Generic.List<string>();

        private string _outputFilterXmlPath = HttpContext.Current.Server.MapPath("~/IDS/output_filter.xml");
        private string _filterXmlPath = HttpContext.Current.Server.MapPath("~/IDS/default_filter.xml");
        private string _pageHTML = string.Empty;
        private bool _decodeJS = true;
        private bool _decodeUTF7 = true;
        private bool _scanOutput = true;
        private bool _scanCookies = true;
        private bool _scanHeader = true;
        private bool _scanGet = true;
        private bool _scanPost = true;
        private bool _scanKeys = true;
        #endregion

        #region Events and Delegates

        /// <summary>
        /// An event that fires when the IDS detects malicious output
        /// </summary>
        public event IDSEvent OnIDSEvents;

        #endregion

        #region Protected Methods
        /// <summary>
        /// The Secure Page's OnInit event handler
        /// </summary>
        /// <param name="e">The Page Init EventArgs</param>
        protected override void OnInit(EventArgs e)
        {
            base.OnInit(e);

            //Create a config object
            IDSGlobalSettings settings = new IDSGlobalSettings();
            IDSPageSettings pageSettings = new IDSPageSettings(settings);

            pageSettings.OnIDSEvent = OnIDSEvent;
            pageSettings.CookieExclusions = _exclusions_cookies;
            pageSettings.PostExclusions = _exclusions_post;
            pageSettings.HeaderExclusions = _exclusions_headers;
            pageSettings.GetExclusions = _exclusions_get;
            pageSettings.DecodeJS = _decodeJS;
            pageSettings.DecodeUTF7 = _decodeUTF7;

            settings.PageSettings.Add(Misc.GetCurrentPageName(), pageSettings);

            WebScanRunner wsr = new WebScanRunner(settings);
            wsr.Run();
        }

        /// <summary>
        /// The SecurePage's Page OnLoad handler
        /// </summary>
        /// <param name="e">The Page Load EventArgs</param>
        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);
        }

        #endregion

        #region Properties

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

        /// <summary>
        /// The event fired when IDS detection occurs
        /// </summary>
        public IDSEvent OnIDSEvent
        {
            get { return OnIDSEvents; }
            set { OnIDSEvents = value; }
        }

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
        /// The path to the Output Filter file
        /// </summary>
        public string OutputFilterXmlPath
        {
            get { return _outputFilterXmlPath; }
            set { _outputFilterXmlPath = value; }
        }

        /// <summary>
        /// The path to the Default Filter file
        /// </summary>
        public string FilterXmlPath
        {
            get { return _filterXmlPath; }
            set { _filterXmlPath = value; }
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
        /// The original page's HTML
        /// <para>This will only be populated once the page's output has been scanned</para>
        /// </summary>
        public string PageHTML
        {
            get { return _pageHTML; }
            set { _pageHTML = value; }
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
        #endregion
    }
}
