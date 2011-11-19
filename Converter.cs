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
    * Charset Converter
    *
    * This class provides functions to decode input.
    *
    * @author   Martin <mhinks@gmail.com>
*/

using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace DOTNETIDS
{
    /// <summary>
    /// A class to convert characters
    /// </summary>
    internal static class CharsetConverter
    {
        #region Internal Methods
        /// <summary>
        /// Filter out ascii representations of UTF7 input
        /// </summary>
        /// <param name="input">The input</param>
        /// <returns>The re-encoded input</returns>
        internal static string convertFromUTF7(string input)
        {
            if (input == null) return String.Empty;
            return Encoding.UTF7.GetString(Encoding.Convert(Encoding.UTF7, Encoding.ASCII, UTF7Encoding.ASCII.GetBytes(input)));
        }

        internal static string convertCentrifuge(string input)
        {
            /*# replace all non-special chars
            $string =  preg_replace('/[\w\s\n\p{L}]/m', NULL, $exploit);
            
            # split string into an array, unify and sort
            $array = str_split($string);
            $array = array_unique($array);
            asort($array);
            
            # normalize certain tokens
            $string = implode($array);
            $string = preg_replace('/[()[\]{}]/', '(', $string);
            $string = preg_replace('/["\'`]/', '"', $string);
            $string = preg_replace('/[!?,.:;]/', ':', $string);
            $string = preg_replace('/[=+-\/*~|]/', '+', $string);
            $string = preg_replace('/[§$%&#@]/', NULL, $string);
            
            # sort again, implode and print result
            $array = str_split($string);
            asort($array); 
            $string = implode($array);           
            
            echo $string . '<br />';*/

            string ret = Regex.Replace(input, @"[\w\s\n\p{L}]", "", RegexOptions.Multiline);

            char[] c = ret.ToCharArray();

            List<char> thechars = new List<char>();

            foreach (char ch in c)
            {
                if (!thechars.Contains(ch))
                {
                    thechars.Add(ch);
                }
            }

            thechars.Sort();

            thechars.Remove('§');
            thechars.Remove('$');
            thechars.Remove('%');
            thechars.Remove('%');
            thechars.Remove('&');
            thechars.Remove('#');
            thechars.Remove('@');

            for (int i = 0; i < thechars.Count; i++)
            {
                string s = thechars[i].ToString();

                s = Regex.Replace(s, @"[()[\]{}]", "(");
                s = Regex.Replace(s, @"[""\'`]", "\"");
                s = Regex.Replace(s, @"[!?,.:;]", ":");
                s = Regex.Replace(s, @"[=+-\/*~|]", "+");
                
                thechars[i] = s.ToCharArray()[0];
            }

            thechars.Sort();

            ret = string.Empty;

            foreach (char ch in thechars)
            {
                ret += ch;
            }

            if (ret == string.Empty)
            {
                return string.Empty;
            }
            else
            {
                return "[" + ret + "]";
            }
        }

        internal static string convertQuotes(string input)
        {
            List<string> quotes = new List<string>();
            quotes.Add("'");
            quotes.Add("`");
            quotes.Add("Â´");
            quotes.Add("â€™");
            quotes.Add("â€");

            string retval = input;

            foreach (string s in quotes)
            {
                retval = retval.Replace(s, "\"");
            }

            if (retval == input)
            {
                return string.Empty;
            }
            else
            {
                return "[" + retval + "]";
            }
        }

        internal static string convertConcats(string input)
        {
            string retval = input;

            List<string> concats = new List<string>();
            concats.Add(@"(""\s*[\W]+\s*\n*"")*");
            concats.Add(@"("";\w\s*\\+=\s*\w?\s*\n*"")*");
            concats.Add(@"(""[|&;]+\s*[^|&\n]*[|&]+\s*\n*""?)*");
            concats.Add(@"("";\s*\w+\W+\w*\s*[|&]*"")*");
            concats.Add("(?:\"?\\+[^\"]*\")");

            foreach (string s in concats)
            {
                retval = Regex.Replace(retval, s, string.Empty, RegexOptions.Singleline);
            }

            if (retval == input)
            {
                return string.Empty;
            }
            else
            {
                return "[" + retval + "]";
            }
        }

        internal static string convertComments(string input)
        {
            string retval = input;

            if (Regex.IsMatch(input, @"(?:\<!-|-->|\/\*|\*\/|\/\/\W*\w+\s*$)|(?:(?:#|--|{)\s*$)", RegexOptions.Singleline))
            {
                List<string> comments = new List<string>();

                comments.Add(@"(?:(?:<!)(?:(?:--(?:[^-]*(?:-[^-]+)*)--\s*)*)(?:>))");
                comments.Add(@"(?:(?:\/\*\/*[^\/\*]*)+\*\/)");
                comments.Add(@"(?:(?:\/\/|--|#|{).*)");

                foreach (string s in comments)
                {
                    retval = Regex.Replace(retval, s, string.Empty, RegexOptions.Singleline);
                }
            }

            if (retval == input)
            {
                return string.Empty;
            }
            else
            {
                return "[" + retval + "]";
            }
        }

        /// <summary>
        /// Filters out JavaScript fromCharCode input
        /// </summary>
        /// <param name="input">The input</param>
        /// <returns>The re-encoded input</returns>
        internal static string convertFromJSCharcode(string input)
        {
            string retval = string.Empty;

            if (!input.Contains(","))
            {
                return string.Empty;
            }

            //Clean the input
            CleanCharcode(ref input);

            Regex re = new Regex(string.Format(@"
                  {0}                       # Match first opening delimiter
                  (?<inner>
                    (?>
                        {0} (?<LEVEL>)      # On opening delimiter push level
                      | 
                        {1} (?<-LEVEL>)     # On closing delimiter pop level
                      |
                        (?! {0} | {1} ) .   # Match any char unless the opening   
                    )+                      # or closing delimiters are in the lookahead string
                    (?(LEVEL)(?!))          # If level exists then fail
                  )
                  {1}                       # Match last closing delimiter
                  ", "\\(", "\\)"),
                  RegexOptions.IgnorePatternWhitespace | RegexOptions.IgnoreCase);

            MatchCollection mc = re.Matches(input);

            foreach (Match m in mc)
            {
                if (m.Success)
                {
                    string converted = "";

                    string[] toconvert = m.Groups["inner"].Value.Split(',');

                    foreach (string charcode in toconvert)
                    {
                        string sCharCode = charcode;

                        //Convert hex
                        ConvertHex(ref sCharCode);

                        //Convert octal
                        ConvertOctal(ref sCharCode);

                        try
                        {
                            ExpressionParser.RPNParser rpn = new ExpressionParser.RPNParser();
                            Int64 iCharCode = (Int64)rpn.EvaluateExpression(sCharCode, Type.GetType("System.Int64"), false, null);

                            converted += (char)iCharCode;
                        }
                        catch (Exception)
                        {
                            //Put the original input back in
                            converted += sCharCode;
                        }
                    }

                    retval += "[" + converted + "]";
                }
            }

            return retval;
        }
        #endregion

        #region Private Methods

        private static void CleanCharcode(ref string sCharCode)
        {
            sCharCode = sCharCode.Trim();
            sCharCode = Regex.Replace(sCharCode, "\\s", "");
            sCharCode = Regex.Replace(sCharCode, "\\w+=", "");
        }

        private static void ConvertOctal(ref string sCharCode)
        {
            //Deal with 0101 etc.
            sCharCode = Regex.Replace(sCharCode, @"(?:\D|^)0+(\d+)", new MatchEvaluator(OctalMatcher), RegexOptions.IgnoreCase);
        }

        private static void ConvertHex(ref string sCharCode)
        {
            //Deal with 0x64 etc.
            sCharCode = Regex.Replace(sCharCode, @"(?:0x0*(\d\d?))", new MatchEvaluator(HexMatcher), RegexOptions.IgnoreCase);
        }

        private static string HexMatcher(Match m)
        {
            try
            {
                return int.Parse(m.Groups[1].Value.ToString(), System.Globalization.NumberStyles.AllowHexSpecifier).ToString();
            }
            catch (Exception)
            {
                return m.ToString();
            }
        }

        private static string OctalMatcher(Match m)
        {
            try
            {
                return BaseToDecimal(m.Groups[1].Value.ToString(), 8).ToString();
            }
            catch (Exception)
            {
                return m.ToString();
            }
        }

        private static int BaseToDecimal(string sBase, int numbase)
        {
            int dec = 0;
            int b;
            int iProduct = 1;
            string sHexa = "";
            if (numbase > base10)
                for (int i = 0; i < cHexa.Length; i++)
                    sHexa += cHexa.GetValue(i).ToString();
            for (int i = sBase.Length - 1; i >= 0; i--, iProduct *= numbase)
            {
                string sValue = sBase[i].ToString();
                if (sValue.IndexOfAny(cHexa) >= 0)
                    b = iHexaNumeric[sHexa.IndexOf(sBase[i])];
                else
                    b = (int)sBase[i] - asciiDiff;
                dec += (b * iProduct);
            }
            return dec;
        }

        const int base10 = 10;
        static char[] cHexa = new char[] { 'A', 'B', 'C', 'D', 'E', 'F' };
        static int[] iHexaNumeric = new int[] { 10, 11, 12, 13, 14, 15 };
        static int[] iHexaIndices = new int[] { 0, 1, 2, 3, 4, 5 };
        const int asciiDiff = 48;

        #endregion
    }
}