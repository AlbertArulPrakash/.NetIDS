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
    * Filter Storage Class
    * 
    * This class provides various default functions for gathering filter 
    * patterns to be used later on by the IDS.
    *
    * In case new methods need to be implemented, 
    * Filter_Storage_Abstract::addFilter() can be used to modify the
    * filter set array.
    *
    * @author	Martin <mhinks@gmail.com>
*/

using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Xml;

namespace DOTNETIDS
{
    /// <summary>
    /// Contains methods for loading Filters from various locations
    /// </summary>
    internal class Storage : FilterStorage
    {
        #region Constructors
        /// <summary>
        /// Load Filters from an XML document
        /// </summary>
        /// <param name="XMLSource">An XMLDocument</param>
        /// <param name="FilterType">The type of Filter to output</param>
        internal Storage(XmlDocument XMLSource, Type FilterType)
            : base()
        {
            XmlNode xmlNode = XMLSource.DocumentElement;

            XmlNodeList nodeList = xmlNode.SelectNodes("/filters/filter");

            foreach (XmlNode filter in nodeList)
            {
                object[] paramlist = new object[4];
                
                foreach (XmlNode child in filter)
                {
                    switch (child.Name)
                    {
                        case "rule":
                            paramlist[0] = child.InnerText;
                            break;
                        case "description":
                            paramlist[3] = child.InnerText;
                            break;
                        case "tags":
                            List<string> tags = new List<String>();

                            foreach (XmlNode tag in child)
                            {
                                tags.Add(tag.InnerText);
                            }

                            paramlist[1] = tags;
                            break;
                        case "impact":
                            paramlist[2] = int.Parse(child.InnerText);
                            break;
                    }

                }

                Filter filterToAdd = (Filter)Activator.CreateInstance(FilterType, paramlist);

                base.AddFilter(filterToAdd);
            }

        }
        #endregion
    }

    /// <summary>
    /// The base FilterStorage class
    /// </summary>
    internal abstract class FilterStorage
    {
        #region Private Fields
        private List<Filter> _filterSet = new List<Filter>();
        #endregion

        #region Internal Properties
        /// <summary>
        /// The set of Filters
        /// </summary>
        internal List<Filter> FilterSet
        {
            get { return _filterSet; }
            set { _filterSet = value; }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Blank constructor visible only to derived classes
        /// </summary>
        protected internal FilterStorage()
        {
        }
        #endregion

        #region Internal Methods
        /// <summary>
        /// Construct a FilterStorage object
        /// </summary>
        /// <param name="filterSet">The set of Filters to use</param>
        internal FilterStorage(List<Filter> filterSet)
        {
            FilterSet = filterSet;
        }

        /// <summary>
        /// Add a filter to the filter set
        /// </summary>
        /// <param name="filter">The filter to add</param>
        internal void AddFilter(Filter filter)
        {
            FilterSet.Add(filter);
        }
        #endregion
    }
}
