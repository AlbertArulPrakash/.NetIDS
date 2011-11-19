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
    * IDS event object
    *
    * This class represents a certain event which has been occured while applying
    * the filters to the given data. It aggregates a bunch of IDS_Filter_Abstract
    * implementations and is a assembled in IDS_Report.
    *
    * @author	Martin <mhinks@gmail.com>
*/

using System;
using System.Collections.Generic;
using System.Text;

namespace DOTNETIDS
{
    /// <summary>
    /// An event during the IDS' detection process
    /// </summary>
    public class Event
    {
        #region Private Fields
        private string _name = "";
        private string _value = "";
        private List<Filter> _filters = new List<Filter>();
        private int _impact = 0;
        private List<string> _tags = new List<string>();
        #endregion

        #region Properties
        /// <summary>
        /// The value passed to the Filters
        /// </summary>
        public string Value
        {
            get { return _value; }
        }

        /// <summary>
        /// The name of the event
        /// </summary>
        public string Name
        {
            get { return _name; }
        }

        /// <summary>
        /// The Filters of the event
        /// </summary>
        public List<Filter> Filters
        {
            get { return _filters; }
        }

        /// <summary>
        /// The impact of the event
        /// </summary>
        public int Impact
        {
            get
            {
                //Calculate the impact
                _impact = 0;

                foreach (Filter f in _filters)
                {
                    _impact += f.Impact;
                }

                return _impact;
            }
        }

        /// <summary>
        /// The tags of the event
        /// </summary>
        public List<string> Tags
        {
            get
            {
                _tags = new List<string>();

                foreach (Filter f in _filters)
                {
                    foreach (string t in f.Tags)
                    {
                        if (!_tags.Contains(t))
                        {
                            _tags.Add(t);
                        }
                    }
                }

                return _tags;
            }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Construct an event object
        /// </summary>
        /// <param name="name">The event's name</param>
        /// <param name="value">The event's value</param>
        /// <param name="filters">The event's filters</param>
        internal Event(string name, string value, List<Filter> filters)
        {
            _name = name;
            _value = value;
            _filters = filters;
        }
        #endregion
    }
}
