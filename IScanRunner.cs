using System;
using System.Collections.Generic;
using System.Text;

namespace DOTNETIDS
{
    public interface IScanRunner
    {
        void WriteResponse(string AlternativeOutput);

        void WriteResponse();

        string PageHTML { get;}
    }
}
