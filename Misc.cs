using System;
using System.Collections.Generic;
using System.Text;

namespace DOTNETIDS
{
    internal class Misc
    {
        internal static string GetCurrentPageName()
        {
            string sPath = System.Web.HttpContext.Current.Request.Url.AbsolutePath;
            System.IO.FileInfo oInfo = new System.IO.FileInfo(sPath);
            string sRet = oInfo.Name;
            return sRet;
        }

        internal static Type ResolveType(string assemblyname, string typename)
        {
            //Attempt to resolve this as a fully qualified name
            try
            {
                Type t = System.Type.GetType(typename + "," + assemblyname);

                if (t != null) return t;
            }
            catch (Exception) { }

            throw new ApplicationException("Unable to bind to the specified assembly and namespace-typename.");
        }
    }
}
