using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.Owin;
using LNF;
using LNF.Impl;

//Authentication.Models.OwinRequestContextProvider

namespace Authentication.Models
{
    public class OwinRequestContextProvider : WebContextProvider
    {
        private IContext _context;

        public override IContext Current
        {
            get
            {
                if (_context == null)
                    _context = new OwinRequestContext();
                return _context;
            }
        }
    }

    public class OwinRequestContext : WebContext
    {
        public override T GetItem<T>(string key)
        {
            return HttpContext.Current.GetOwinContext().Get<T>(key);
        }

        public override void SetItem<T>(string key, T item)
        {
            HttpContext.Current.GetOwinContext().Set<T>(key, item);
        }
    }
}