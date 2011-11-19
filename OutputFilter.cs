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
    * Output filter object
    *
    * This class represents a stream which will examine outgoing page output.
    *
    * @author	Martin <mhinks@gmail.com>
*/

using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Xml;


namespace DOTNETIDS
{
    /// <summary>
    /// A class that can examine a Page's output
    /// </summary>
    public class OutputFilter : System.IO.Stream
    {
        #region Private Fields
        private Stream _baseStream;
        private long _position;
        private string _output = String.Empty;
        private Encoding _enc;
        private System.Web.UI.Page _page;
        private List<byte> _masterbytes = new List<byte>();
        private Report _report = null;
        internal Storage _store = null;
        private bool _continued = false;
        private bool _JSDecode = true;
        private bool _UTF7Decode = true;
        #endregion

        #region Properties
        /// <summary>
        /// Decode JavaScript fromCharCode-style injections
        /// </summary>
        public bool JSDecode
        {
            get { return _JSDecode; }
            set { _JSDecode = value; }
        }

        /// <summary>
        /// Decode UTF7 injections
        /// </summary>
        public bool UTF7Decode
        {
            get { return _UTF7Decode; }
            set { _UTF7Decode = value; }
        }

        /// <summary>
        /// A report of the output filter
        /// </summary>
        public Report Report
        {
            get { return _report; }
            set { _report = value; }
        }

        /// <summary>
        /// The Page this response is based on
        /// </summary>
        public System.Web.UI.Page Page
        {
            get { return _page; }
            set { _page = value; }
        }

        /// <summary>
        /// The generated markup from the page
        /// </summary>
        public string Output
        {
            get { return _output; }
            set { _output = value; }
        }

        /// <summary>
        /// Indicates whether the stream is readable
        /// </summary>
        public override bool CanRead
        {
            get { return true; }
        }

        /// <summary>
        /// Indicates whether the stream is seekable
        /// </summary>
        public override bool CanSeek
        {
            get { return true; }
        }

        /// <summary>
        /// Indicates whether the stream is writable
        /// </summary>
        public override bool CanWrite
        {
            get { return true; }
        }

        /// <summary>
        /// The length of the stream
        /// </summary>
        public override long Length
        {
            get { return _baseStream.Length; }
        }

        /// <summary>
        /// The stream's current position
        /// </summary>
        public override long Position
        {
            get { return _position; }
            set { _position = value; }
        }

        #endregion

        #region Delegates/Events
        /// <summary>
        /// A delegate for OnPageReady
        /// </summary>
        /// <param name="oF">An OutputFilter object</param>
        public delegate void PageReadyEvent(DOTNETIDS.OutputFilter oF);
        
        /// <summary>
        /// An event that fires when the page output is ready and has been scrutinised by the IDS
        /// </summary>
        public event PageReadyEvent OnPageReady;
        #endregion

        #region Constructors
        /// <summary>
        /// Construct an Output Filter object
        /// </summary>
        /// <param name="baseStream">The underlying stream to filter</param>
        /// <param name="page">The page this request is based on</param>
        /// <param name="encoder">An encoding object</param>
        /// <param name="xmlPath">The path to the output filters</param>
        public OutputFilter(Stream baseStream, System.Web.UI.Page page, Encoding encoder, string xmlPath)
        {
            _baseStream = baseStream;
            _enc = encoder;
            _page = page;
            
            XmlDocument xd = new XmlDocument();
            xd.Load(xmlPath);
            _store = new Storage(xd, typeof(RegexFilter));
        }

        /// <summary>
        /// Construct an Output Filter object using the same filters as an already existing IDS object
        /// </summary>
        /// <param name="baseStream">The underlying stream to filter</param>
        /// <param name="page">The page this request is based on</param>
        /// <param name="encoder">An encoding object</param>
        /// <param name="ids">The IDS containing the preloaded filters</param>
        public OutputFilter(Stream baseStream, System.Web.UI.Page page, Encoding encoder, IDS ids)
        {
            _baseStream = baseStream;
            _enc = encoder;
            _page = page;
            _store = ids._store;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Flush the contents of the stream
        /// </summary>
        public override void Flush()
        {
            _baseStream.Flush();
        }

        /// <summary>
        /// Read from the stream
        /// </summary>
        /// <param name="buffer">The buffer to fill</param>
        /// <param name="offset">The offset to read from</param>
        /// <param name="count">The number of bytes to read</param>
        /// <returns>The number of bytes read</returns>
        public override int Read(byte[] buffer, int offset, int count)
        {
            return _baseStream.Read(buffer, offset, count);
        }

        /// <summary>
        /// Move the stream to a new position
        /// </summary>
        /// <param name="offset">The offset</param>
        /// <param name="origin">The origin</param>
        /// <returns>The new position</returns>
        public override long Seek(long offset, SeekOrigin origin)
        {
            return _baseStream.Seek(offset, origin);
        }

        /// <summary>
        /// Set the length of the stream
        /// </summary>
        /// <param name="value">The new length</param>
        public override void SetLength(long value)
        {
            _baseStream.SetLength(value);
        }

        /// <summary>
        /// Write to the stream
        /// </summary>
        /// <param name="buffer">The data to be written</param>
        /// <param name="offset">The offset to write at</param>
        /// <param name="count">The number of bytes to write</param>
        public override void Write(byte[] buffer, int offset, int count)
        {
            //Build up an internal string
            //This can later be filtered

            byte[] data = new byte[count];
            Buffer.BlockCopy(buffer, offset, data, 0, count);

            //Convert to text
            _output += _enc.GetString(data);

            foreach (byte b in data)
            {
                _masterbytes.Add(b);
            }

        }

        /// <summary>
        /// Close the stream
        /// </summary>
        public override void Close()
        {
            //At this point the stream is closed and we can do Intrusion Detection
            //So call the attached events

            //Do IDS
            IDS ids = new IDS(this);

            ids.UTF7Decode = UTF7Decode;
            ids.JSDecode = JSDecode;
            

            ids.Run();

            this.Report = ids.Report;

            //Call event
            if (OnPageReady != null) OnPageReady(this);

            //Finish page if not done by events
            if (!_continued)
            {
                _continued = true;

                throw new ApplicationException("When using a PageOutput filter you MUST call either WriteResponse() or WriteResponse(string).");
            }
        }

        /// <summary>
        /// Write the original response to the client
        /// </summary>
        public void WriteResponse()
        {
            _continued = true;

            byte[] data = _masterbytes.ToArray();

            if (data.Length > 0)
            {
                _baseStream.Write(data, 0, data.Length);
            }

            base.Close();
        }

        /// <summary>
        /// Write a different response to the client
        /// </summary>
        public void WriteResponse(string response)
        {
            _continued = true;

            byte[] data = _enc.GetBytes(response);

            if (data.Length > 0)
            {
                _baseStream.Write(data, 0, data.Length);
            }

            base.Close();
        }

        #endregion

        #region Internal Methods
        /// <summary>
        /// Get an object that can intercept control rendering
        /// </summary>
        /// <returns>A ControlRenderInterceptor object</returns>
        internal ControlRenderInteceptor GetInterceptor()
        {
            return new ControlRenderInteceptor(new ControlRenderInterceptorTW(_enc));
        }
        #endregion
    }

    /// <summary>
    /// A class to intercept control rendering
    /// </summary>
    internal class ControlRenderInteceptor : System.Web.UI.HtmlTextWriter
    {
        #region Private Fields
        string _lastOutput = "";
        #endregion

        #region Properties
        /// <summary>
        /// The last output written to this writer
        /// </summary>
        internal string LastOutput
        {
            get { return _lastOutput; }
            set { _lastOutput = value; }
        }
        #endregion

        #region Constructors
        internal ControlRenderInteceptor(TextWriter tw)
            : base(tw)
        {
        }
        #endregion

        #region Public Methods
        public override void Write(string s)
        {
            LastOutput = s;
        }
        #endregion
    }

    /// <summary>
    /// An empty TextWriter implementation
    /// </summary>
    internal class ControlRenderInterceptorTW : TextWriter
    {
        #region Constructors
        internal ControlRenderInterceptorTW(Encoding encoding)
        {
        }
        #endregion

        #region Properties
        public override Encoding Encoding
        {
            get { return Encoding.ASCII; }
        }
        #endregion
    }
}
