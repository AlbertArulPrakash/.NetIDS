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
    * Filter Class
    * 
    * This class provides an implementation of the Filter object.
    *
    * @author	Martin <mhinks@gmail.com>
*/

using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace DOTNETIDS
{
    /// <summary>
    /// The abstract base Filter class
    /// </summary>
    public abstract class Filter
    {
        #region Private Fields
        private string _rule;
        private List<string> _tags = new List<string>();
        private int _impact = 0;
        private string _description = "";
        #endregion

        #region Properties
        /// <summary>
        /// The Filter's description
        /// </summary>
        public string Description
        {
            get { return _description; }
            set { _description = value; }
        }

        /// <summary>
        /// The Filter's tags
        /// </summary>
        public List<string> Tags
        {
            get { return _tags; }
            set { _tags = value; }
        }

        /// <summary>
        /// The Filter's impact level
        /// </summary>
        public int Impact
        {
            get { return _impact; }
            set { _impact = value; }
        }

        /// <summary>
        /// The Filter's rule
        /// </summary>
        public string Rule
        {
            get { return _rule; }
            set { _rule = value; }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Create a new filter object
        /// </summary>
        /// <param name="rule">The Filter's rule</param>
        /// <param name="tags">The Filter's tags</param>
        /// <param name="impact">The Filter's impact level</param>
        /// <param name="description">The Filter's description</param>
        internal Filter(string rule, List<string> tags, int impact, string description)
        {
            Rule = rule;
            Tags = tags;
            Impact = impact;
            Description = description;
        }

        /// <summary>
        /// A method to ascertain if the Filter matched the input
        /// </summary>
        /// <param name="MatchText">The input to match against</param>
        /// <returns>True if matched, false otherwise</returns>
        public abstract bool Match(string MatchText);
        #endregion
    }

    /// <summary>
    /// A Filter that uses Regular Expressions for its matching
    /// </summary>
    public class RegexFilter : Filter
    {
        #region Constructors
        /// <summary>
        /// Create a new regex filter object
        /// </summary>
        /// <param name="rule">The Filter's rule</param>
        /// <param name="tags">The Filter's tags</param>
        /// <param name="impact">The Filter's impact level</param>
        /// <param name="description">The Filter's description</param>
        public RegexFilter(string rule, List<string> tags, int impact, string description)
            : base(rule, tags, impact, description)
        {
        }
        #endregion

        MatchCollection m;

        public MatchCollection Matches
        {
            get { return m; }
        }

        #region Public Methods
        /// <summary>
        /// Match a regular expression rule against the input
        /// </summary>
        /// <param name="MatchText">The input</param>
        /// <returns>True if matched, false otherwise</returns>
        public override bool Match(string MatchText)
        {
            if (MatchText == String.Empty || MatchText == null) return false;
            m = Regex.Matches(MatchText, Rule, RegexOptions.IgnoreCase);

            return m.Count > 0;            
        }

        public string Replace(string MatchText, MatchEvaluator me)
        {
            return Regex.Replace(MatchText, Rule, me, RegexOptions.IgnoreCase);
        }
        #endregion
    }

    /// <summary>
    /// A Filter that uses Regular Expressions for its matching
    /// </summary>
    internal class NullByteFilter : Filter
    {
        #region Constructors
        /// <summary>
        /// Create a new null byte filter object
        /// </summary>
        public NullByteFilter()
            : base("Null Byte Filter", new List<string>(), 3, "Internal null byte detection")
        {
            base.Tags.Add("xss");
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Match the null byte rule against the input
        /// </summary>
        /// <param name="MatchText">The input</param>
        /// <returns>True if matched, false otherwise</returns>
        public override bool Match(string MatchText)
        {
            if (MatchText == null) return false;

            //Look for Null Bytes
            byte[] bytes = System.Text.Encoding.ASCII.GetBytes(MatchText);
            foreach (byte b in bytes)
            {
                if (b == 0)
                {
                    return true;
                }
            }

            return false;
        }
        #endregion
    }
}
