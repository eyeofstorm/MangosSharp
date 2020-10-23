//
//  Copyright (C) 2013-2020 getMaNGOS <https://getmangos.eu>
//  
//  This program is free software. You can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation. either version 2 of the License, or
//  (at your option) any later version.
//  
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY. Without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//  
//  You should have received a copy of the GNU General Public License
//  along with this program. If not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//

using System;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using static Microsoft.Extensions.Hosting.Host;

namespace Mangos.SignalR
{
    public class ProxyServer<T> : IDisposable where T : Hub
    {
        private readonly IHost _webhost;

        public ProxyServer(IPAddress address, int port, T hub)
        {
            if (address == null) throw new ArgumentNullException(nameof(address));
            if (hub == null) throw new ArgumentNullException(nameof(hub));
            var hostbuilder = CreateDefaultBuilder();
            if (hostbuilder != null)
            {
                hostbuilder.ConfigureWebHost(x =>
                {
                    if (x == null) return;
                    ConfigureWebHost(x, address, port, hub);
                });
                _webhost = hostbuilder.Build();
            }

            _webhost?.Start();
        }

        private void ConfigureWebHost(IWebHostBuilder webHostBuilder, IPAddress address, int port, T hub)
        {
            if (webHostBuilder == null) throw new ArgumentNullException(nameof(webHostBuilder));
            if (address == null) throw new ArgumentNullException(nameof(address));
            if (hub == null) throw new ArgumentNullException(nameof(hub));
            webHostBuilder.UseKestrel(x =>
            {
                if (x == null) throw new ArgumentNullException(nameof(x));
                x.Listen(address, port);
            });
            webHostBuilder.ConfigureLogging(x =>
            {
                if (x == null) throw new ArgumentNullException(nameof(x));
                x.ClearProviders();
            });
            webHostBuilder.ConfigureServices(x =>
            {
                if (x == null) throw new ArgumentNullException(nameof(x));
                if (x.Count == 0) throw new ArgumentException("Value cannot be an empty collection.", nameof(x));
                ConfigureServices(x, hub);
            });
            webHostBuilder.Configure(ConfigureApplication);
        }

        private void ConfigureServices(IServiceCollection serviceCollection, T hub)
        {
            if (serviceCollection == null) throw new ArgumentNullException(nameof(serviceCollection));
            if (hub == null) throw new ArgumentNullException(nameof(hub));
            if (serviceCollection.Count == 0)
                throw new ArgumentException("Value cannot be an empty collection.", nameof(serviceCollection));
            serviceCollection.AddSignalR(ConfigureSignalR);
            serviceCollection.AddSingleton(hub);
        }

        private static void ConfigureApplication(IApplicationBuilder applicationBuilder)
        {
            if (applicationBuilder == null) throw new ArgumentNullException(nameof(applicationBuilder));
            applicationBuilder.UseRouting();
            applicationBuilder.UseEndpoints(x =>
            {
                if (x == null) throw new ArgumentNullException(nameof(x));
                x.MapHub<T>(string.Empty);
            });
        }

        private static void ConfigureSignalR(HubOptions hubOptions)
        {
            if (hubOptions == null) throw new ArgumentNullException(nameof(hubOptions));
            hubOptions.EnableDetailedErrors = true;
        }

        public void Dispose()
        {
            _webhost?.Dispose();
        }
    }
}