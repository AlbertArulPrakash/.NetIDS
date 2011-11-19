using System;
using System.Collections.Generic;
using System.Text;

namespace DOTNETIDS.Tests
{
    public static class ConverterTests
    {
        public static bool UTF7DecodeTest()
        {
            string val = CharsetConverter.convertFromUTF7("+AFwAIg-+ADw-+AD4-+AFs-+AF0-+AHs-+AH0-+AFw-+ADs-+ACM-+ACY-+ACU-+ACQ-+AD0-+AGA-+AHw-+ACo-+AF4-");

            if (val != "\\\"<>[]{}\\;#&%$=`|*^")
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        public static bool QuotesDecodeTest()
        {
            string val = CharsetConverter.convertQuotes("\"'´�’");

            if (val != "[" + "\"\"\"\"\"" + "]")
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        public static bool JSDecodeTest()
        {
            string val = CharsetConverter.convertFromJSCharcode("(48,(48),(48*2)/2,48+1-1)");

            if (val != "[" + "0000" + "]")
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        public static bool CommentDecodeTest()
        {
            string val = CharsetConverter.convertComments("Te/*test*/st<!--TEST-->//TEST");

            if (val != "[" + "Test" + "]")
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        public static bool ConcatDecodeTest()
        {
            string val = CharsetConverter.convertConcats("a=0||\"ev\"+\"al\",b=0||1[a](\"loca\" + \"tion.hash\"),c=0||\"sub\"+\"str\",1[a](b[c](1));");

            if (val != "[" + "a=0||\"eval\",b=0||1[a](\"location.hash\"),c=0||\"substr\",1[a](b[c](1));" + "]")
            {
                return false;
            }
            else
            {
                return true;
            }
        }
    }
}
