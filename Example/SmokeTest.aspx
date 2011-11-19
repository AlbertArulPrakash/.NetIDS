<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="SmokeTest.aspx.cs" Inherits="SmokeTest.SmokeTest" ValidateRequest="false" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <title>.NETIDS &raquo; Smoketest</title>
        <link rel="Stylesheet" type="text/css" href="style.css" />
    </head>
    <body>
        <div id="page">

            <h1>.NETIDS &raquo; Smoketest</h1>
            <div id="content">
                <h2>Smoketest</h2>
                <div class="text">
                    Please feel free to inject malicious input to stress test the .NETIDS - you can 
                    either do this via the form, via any GET (querystring) parameters 
                    "<a href="SmokeTest.aspx?test1=%22%3EXXX&amp;test2=param2">like this</a>, via any cookies and via HTTP headers".
                </div>

                <div class="text">
                    Input not considered malicious by the IDS will be displayed unfiltered - 
                    input considered malicious will be displayed sanitized (So anything malicious not detected by the .NETIDS will be executed).
                </div>
                <div class="text">
                    If you manage to inject an XSS without being noticed by the .NETIDS please 
                    contact us via the <a href="http://code.google.com/p/dotnetids" target="_blank">.NETIDS Google Code Group</a> and 
                    help us to improve this software! Any other comments and opinions are also highly appreciated.
                    <br /><br />Greetings and thanks in advance,<br />the .NETIDS team
                </div>
                
                <form id="Form1" runat="server">
                <asp:PlaceHolder runat="server" ID="idsoutput" />
                 
                 <div id="theform">
                        <fieldset>
                            <asp:TextBox Rows="6" Columns="60" id="dotnetidstestform" runat="server" TextMode="MultiLine"></asp:TextBox>
                            <asp:Button id="SubmitButton" runat="server" Text="Send" /> <asp:CheckBox ID="UTF7Decode" runat="server" Text=" UTF7 Decode" Checked="true" /> <asp:CheckBox ID="JSDecode" runat="server" Text=" JavaScript (fromCharCode) Decode" Checked="true" />&nbsp;
                        </fieldset>
                </div>
                </form>
                <div id="footer">

                    &copy; <a href="http://code.google.com/p/dotnetids">PHPIDS and.NETIDS teams</a> 
                    2007                </div>
            </div>
            <div id="sidebar">
                <div id="selfpromotion">
                    <h2>Related stuff</h2>
                    <ul>

                        <li>
                            <a href="http://code.google.com/p/dotnetids/">.NETIDS Google Code</a>
                        </li>
                        <li>
                            <a href="http://www.the-mice.co.uk/switch/">Switch/Twitch</a>
                        </li>
                        <li>
                            <a href="http://phpids.org/">PHPIDS</a>
                        </li>                    
                        <li>
                            <a href="http://h4k.in/encoding">PHP charset encoder</a>

                        </li>
                        <li>
                            <a href="http://h4k.in/dataurl">data: URL testcases</a>
                        </li>
                    </ul>
                </div>
            </div>
        </div>

    </body>
</html>