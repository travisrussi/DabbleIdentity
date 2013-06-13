/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System;
using System.Runtime.Caching;
using NLog;

namespace Thinktecture.IdentityServer.Repositories
{
    public class MemoryCacheRepository : ICacheRepository
    {
        static MemoryCache _cache = new MemoryCache("Thinktecture.IdentityServer.Caching");
        static Logger logger = LogManager.GetCurrentClassLogger();

        public void Put(string name, object value, int ttl)
        {
            logger.Info(String.Format("Adding {0} to cache", name));
            _cache.Add(name, value, DateTimeOffset.Now.AddHours(ttl));
        }

        public object Get(string name)
        {
            var item = _cache.Get(name);
            logger.Info(String.Format("Fetching {0} from cache: {1}", name, item == null ? "miss" : "hit"));

            return item;
        }

        public void Invalidate(string name)
        {
            logger.Info(String.Format("Invalidating {0} in cache", name));
            _cache.Remove(name);
        }
    }
}
