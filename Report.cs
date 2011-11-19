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
    * PHP IDS report object
    *
    * The report objects collects a number of events in order to present the
    * filter results. It provides a convenient API to work with the results.
    *
    * @author	Martin <mhinks@gmail.com>
*/

using System;
using System.Collections.Generic;
using System.Text;

namespace DOTNETIDS
{
    /// <summary>
    /// A report of the IDS' findings
    /// </summary>
    public class Report
    {
        #region Private Fields
        private RequestType _requestType = RequestType.Get;
        private List<Event> _events = new List<Event>();
        private List<String> _exclusions = new List<string>();
        private int _impact = 0;
        private List<String> _tags = new List<string>();
        #endregion

        #region Properties
        /// <summary>
        /// The type of request this report was created on
        /// </summary>
        public RequestType RequestType
        {
            get { return _requestType; }
            set { _requestType = value; }
        }

        /// <summary>
        /// A list of Exclusions that this Report operated on
        /// </summary>
        public List<String> Exclusions
        {
            get { return _exclusions; }
            set { _exclusions = value; }
        }

        /// <summary>
        /// A list of events within the IDS detection process
        /// </summary>
        public List<Event> Events
        {
            get { return _events; }
        }
        
        /// <summary>
        /// The Impact rating of the input
        /// </summary>
        public int Impact
        {
            get
            {
                _impact = 0;

                foreach (Event e in Events)
                {
                    foreach (Filter f in e.Filters)
                    {
                        _impact += f.Impact;
                    }
                }

                return _impact;
            }
        }

        /// <summary>
        /// A list of tags identify what types of attack were detected
        /// </summary>
        public List<String> Tags
        {
            get
            {
                List<string> tags = new List<string>();
                foreach (Event e in Events)
                {
                    foreach (string s in e.Tags)
                    {
                        if (!tags.Contains(s))
                        {
                            tags.Add(s);
                        }
                    }
                }

                return tags;
            }
        }
        #endregion

        #region Constructors
        internal Report(RequestType requestType)
        {
            _requestType = requestType;
        }

        internal Report(List<Event> events, RequestType requestType)
        {
            _events = events;
            _requestType = requestType;
        }
        #endregion

        #region Internal Methods
        internal void AddEvent(Event e)
        {
            _events.Add(e);
        }
        #endregion
    }
}
