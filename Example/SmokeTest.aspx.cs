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
    * SmokeTest
    *
    * This page shows off features of the IDS.
    *
    * @author   Martin <mhinks@gmail.com>
*/

using System;
using System.Data;
using System.Configuration;
using System.Collections;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Web.UI.HtmlControls;
using DOTNETIDS;

namespace SmokeTest
{
    public partial class SmokeTest : SecurePage
    {
        System.Collections.Generic.List<string> values = new System.Collections.Generic.List<string>();
        string _replace = string.Empty;
        bool _found = false;

        protected void Page_Init(object sender, EventArgs e)
        {
            OnIDSEvent += new IDSEvent(IDSEventHandler);
            
            //Set exclusions
            PostExclusions.Add("SubmitButton");
            PostExclusions.Add("UTF7Decode");
            PostExclusions.Add("JSDecode");

            //Set paths if necessary (or use built-in filters)
            //FilterXmlPath = Server.MapPath("~/IDS/default_filter.xml");

            //Set options
            DecodeJS = JSDecode.Checked;
            DecodeUTF7 = UTF7Decode.Checked;

            //Set an exclusion
            //Exclusions.Add("Content-Length");
        }


        public void IDSEventHandler(Report report, IScanRunner Sender)
        {
            switch (report.RequestType)
            {
                case RequestType.Get:
                    if (!ShowReport(report))
                    {
                        WriteAllClearGet(report);
                    }
                    else
                    {
                        _found = true;
                    }
                   
                    break;
                case RequestType.Post:
                    if (!ShowReport(report))
                    {
                        WriteAllClearPost(report);
                    }
                    else
                    {
                        _found = true;
                    }
                    
                    break;
                case RequestType.Cookie:
                    if (!ShowReport(report))
                    {
                        WriteAllClearCookie(report);
                    }
                    else
                    {
                        _found = true;
                    }
                    break;
                case RequestType.Header:
                    if (!ShowReport(report))
                    {
                        WriteAllClearHeader(report);
                    }
                    else
                    {
                        _found = true;
                    }

                    if (!_found)
                    {
                        //NOW WRITE THE SPACE FOR THE OUTPUT PARAMETER
                        Literal outputspace = new Literal();
                        outputspace.Text = WriteAllClearFragmented();
                        _replace = outputspace.Text;
                        idsoutput.Controls.Add(outputspace);
                    }
                    else
                    {
                        //NOW WRITE THE SPACE FOR THE OUTPUT PARAMETER
                        Literal outputspace = new Literal();
                        outputspace.Text = "<h3 class=\"clean\">Fragmented input not written because non-fragmented events were detected.</h3><br/>";
                        _replace = outputspace.Text;
                        idsoutput.Controls.Add(outputspace);
                    }
                    break;
                case RequestType.Output:
                    if (report.Events.Count == 0)
                    {
                        //Write new output with concaternated strings
                        Sender.WriteResponse();
                    }
                    else
                    {
                        if (!_found)
                        {
                            WriteFragmented(report, Sender);
                        }
                        else
                        {
                            Sender.WriteResponse();
                        }
                    }
                    break;
            }
        }

        private string WriteAllClearFragmented()
        {
            //Write out the fragmented input

            string clean = "<h3 class=\"clean\">Fragmented input looks clean: </h3><br/>";
            clean += "<span>";

            foreach (string s in values)
            {
                clean += s;
            }

            clean += "</span>";
            
            return clean;

        }


        private void WriteFragmented(Report report, IScanRunner Sender)
        {
            if (report.Events.Count > 0)
            {
                string output = "";

                //Found a malicious string
                foreach (Event ev in report.Events)
                {
                    output += "<div class=\"result\"><h3>found fragmented injection: </h3></div>";
                    //output += "<div class=\"value\">value: " + Server.HtmlEncode(ev.Value) + "</div>";
                    int impact = 0;

                    foreach (Filter f in ev.Filters)
                    {
                        impact += f.Impact;

                        if (f.Rule.Length > 60)
                        {
                            output += "<div class=\"result\">rule: " + Server.HtmlEncode(f.Rule.Substring(0, 60)) + "...<br />rule-description: <i>" + Server.HtmlEncode(f.Description) + "</i><br />impact: " + f.Impact + "</div>";
                        }
                        else
                        {
                            output += "<div class=\"result\">rule: " + Server.HtmlEncode(f.Rule) + "<br />rule-description: <i>" + Server.HtmlEncode(f.Description) + "</i><br />impact: " + f.Impact + "</div>";
                        }

                    }

                    output += "<div class=\"result\"><h3>Overall impact: <strong style=\"color:red;\">" + ev.Impact + "</strong></h3></div>";
                }

                if (_replace != string.Empty)
                {
                    string newoutput = PageHTML.Replace(_replace, output);
                    Sender.WriteResponse(newoutput);
                }
                else
                {
                    Sender.WriteResponse();
                }

            }
        }

        private void WriteAllClearHeader(Report report)
        {
            foreach (string s in Request.Headers)
            {
                if (!report.Exclusions.Contains(s))
                {
                    values.Add(Request.Headers[s]);

                    //Literal clean = new Literal();
                    //clean.Text = "<h3 class=\"clean\">Clean header parameter: " + s + "</h3><table class=\"clean\"><tr><td><strong>HTML injection</strong></td><td>" + Request.Headers[s] + "</td></tr><tr><td><strong>a href doublequoted</strong></td><td><a href=\"SmokeTest.aspx?test=" + Request.Headers[s] + "\">click</a></td></tr><tr><td><strong>a href singlequoted</strong></td><td><a href='SmokeTest.aspx?test=" + Request.Headers[s] + "'>click</a></td></tr><tr><td><strong>a href no quotes</strong></td><td><a href=SmokeTest.aspx?test=" + Request.Headers[s] + ">click</a></td></tr></table>";
                    //idsoutput.Controls.Add(clean);
                }
            }

            
        }

        private void WriteAllClearCookie(Report report)
        {
            foreach (string s in Request.Cookies.AllKeys)
            {
                if (!report.Exclusions.Contains(s))
                {
                    values.Add(Request.Cookies[s].Value);

                    //Literal clean = new Literal();
                    //clean.Text = "<h3 class=\"clean\">Clean cookie parameter: " + s + "</h3><table class=\"clean\"><tr><td><strong>HTML injection</strong></td><td>" + Request.Cookies[s].Value + "</td></tr><tr><td><strong>a href doublequoted</strong></td><td><a href=\"SmokeTest.aspx?test=" + Request.Cookies[s].Value + "\">click</a></td></tr><tr><td><strong>a href singlequoted</strong></td><td><a href='SmokeTest.aspx?test=" + Request.Cookies[s].Value + "'>click</a></td></tr><tr><td><strong>a href no quotes</strong></td><td><a href=SmokeTest.aspx?test=" + Request.Cookies[s].Value + ">click</a></td></tr></table>";
                    //idsoutput.Controls.Add(clean);
                }
            }
        }

        private void WriteAllClearGet(Report report)
        {
            foreach (string s in Request.QueryString.AllKeys)
            {
                if (!report.Exclusions.Contains(s))
                {
                    values.Add(Request.QueryString[s]);
                    Literal clean = new Literal();
                    clean.Text = "<h3 class=\"clean\">Clean GET parameter: " + s + "</h3><table class=\"clean\"><tr><td><strong>HTML injection</strong></td><td>" + Request.QueryString[s] + "</td></tr><tr><td><strong>a href doublequoted</strong></td><td><a href=\"SmokeTest.aspx?test=" + Request.QueryString[s] + "\">click</a></td></tr><tr><td><strong>a href singlequoted</strong></td><td><a href='SmokeTest.aspx?test=" + Request.QueryString[s] + "'>click</a></td></tr><tr><td><strong>a href no quotes</strong></td><td><a href=SmokeTest.aspx?test=" + Request.QueryString[s] + ">click</a></td></tr></table>";
                    idsoutput.Controls.Add(clean);
                }
            }
        }

        private void WriteAllClearPost(Report report)
        {
            foreach (string s in Request.Form.AllKeys)
            {
                if (!report.Exclusions.Contains(s))
                {
                    values.Add(Request.Form[s]);
                    Literal clean = new Literal();
                    clean.Text = "<h3 class=\"clean\">Clean POST parameter: " + s + "</h3><table class=\"clean\"><tr><td><strong>HTML injection</strong></td><td>" + Request.Form[s] + "</td></tr><tr><td><strong>a href doublequoted</strong></td><td><a href=\"SmokeTest.aspx?test=" + Request.Form[s] + "\">click</a></td></tr><tr><td><strong>a href singlequoted</strong></td><td><a href='SmokeTest.aspx?test=" + Request.Form[s] + "'>click</a></td></tr><tr><td><strong>a href no quotes</strong></td><td><a href=SmokeTest.aspx?test=" + Request.Form[s] + ">click</a></td></tr></table>";
                    idsoutput.Controls.Add(clean);
                }
            }
        }

        private bool ShowReport(Report report)
        {
            if (report == null) return false;

            if (report.Events.Count > 0)
            {
                string output = "";

                //Found a malicious string
                foreach (Event ev in report.Events)
                {
                    
                    output += "<div class=\"result\"><h3>found injection: <br/>";

                    if (ev.Name.Length >= 60)
                    {
                        output += "param: " + Server.HtmlEncode(ev.Name.Substring(0, 60)) + "...<br/>";
                    }
                    else
                    {
                        output += "param: " + Server.HtmlEncode(ev.Name) + "<br/>";
                    }

                    if (ev.Value.Length >= 60)
                    {
                        output += "value: " + Server.HtmlEncode(ev.Value.Substring(0, 60)) + "...</h3></div>";
                    }
                    else
                    {
                        output += "value: " + Server.HtmlEncode(ev.Value) + "</h3></div>";
                    }

                    int impact = 0;

                    foreach (Filter f in ev.Filters)
                    {
                        impact += f.Impact;

                        if (f.Rule.Length > 60)
                        {
                            output += "<div class=\"result\">rule: " + Server.HtmlEncode(f.Rule.Substring(0, 60)) + "...<br />rule-description: <i>" + Server.HtmlEncode(f.Description) + "</i><br />impact: " + f.Impact + "</div>";
                        }
                        else
                        {
                            output += "<div class=\"result\">rule: " + Server.HtmlEncode(f.Rule) + "<br />rule-description: <i>" + Server.HtmlEncode(f.Description) + "</i><br />impact: " + f.Impact + "</div>";
                        }


                    }

                    output += "<div class=\"result\"><h3>Overall impact: <strong style=\"color:red;\">" + ev.Impact + "</strong></h3></div>";
                }

                Literal foundblock = new Literal();
                foundblock.Text = output;

                idsoutput.Controls.Add(foundblock);

                return true;
            }

            return false;

        }
    }

}
