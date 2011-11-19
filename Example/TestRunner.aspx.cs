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

namespace Example
{
    public partial class TestRunner : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            if (DOTNETIDS.Tests.ConverterTests.UTF7DecodeTest())
            {
                results.Text += "UTF7 Decode: PASSED<br/>";
            }
            else
            {
                results.Text += "UTF7 Decode: FAILED<br/>";
            }

            if (DOTNETIDS.Tests.ConverterTests.QuotesDecodeTest())
            {
                results.Text += "Quote Decode: PASSED<br/>";
            }
            else
            {
                results.Text += "Quote Decode: FAILED<br/>";
            }

            if (DOTNETIDS.Tests.ConverterTests.JSDecodeTest())
            {
                results.Text += "JS Decode: PASSED<br/>";
            }
            else
            {
                results.Text += "JS Decode: FAILED<br/>";
            }

            if (DOTNETIDS.Tests.ConverterTests.CommentDecodeTest())
            {
                results.Text += "Comment Decode: PASSED<br/>";
            }
            else
            {
                results.Text += "Comment Decode: FAILED<br/>";
            }

            if (DOTNETIDS.Tests.ConverterTests.ConcatDecodeTest())
            {
                results.Text += "Concat Decode: PASSED<br/>";
            }
            else
            {
                results.Text += "Concat Decode: FAILED<br/>";
            }
        }
    }
}
