//
// Copyright (C) 2013-2020 getMaNGOS <https://getmangos.eu>
//
// This program is free software. You can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation. either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY. Without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//

using System;
using System.Reflection;
using System.Threading.Tasks;
using Mangos.Configuration;
using Mangos.Loggers;
using Mangos.Network.Tcp;
using Mangos.Storage.MySql;
using static System.Console;
using static System.Net.IPEndPoint;
using static System.Reflection.Assembly;

namespace Mangos.Realm
{
    public class RealmServer
    {
        private readonly ILogger _logger;
        private readonly MySqlAccountStorage _accountStorage;
        private readonly IConfigurationProvider<RealmServerConfiguration> _configurationProvider;

        private readonly TcpServer _tcpServer;

        public RealmServer(
            ILogger logger,
            MySqlAccountStorage accountStorage,
            IConfigurationProvider<RealmServerConfiguration> configurationProvider,
            TcpServer tcpServer)
        {
            if (logger != null) _logger = logger;
            if (accountStorage != null) _accountStorage = accountStorage;
            if (configurationProvider != null) _configurationProvider = configurationProvider;
            if (tcpServer != null) _tcpServer = tcpServer;
        }

        public async Task StartAsync()
        {
            LogInitialInformation();

            await ConnectToDatabaseAsync();
            await StartTcpServer();

            ReadLine();
        }

        private async Task ConnectToDatabaseAsync()
        {
            if (_configurationProvider != null)
            {
                var configuration = await _configurationProvider.GetConfigurationAsync();
                if (configuration == null) throw new ArgumentNullException(nameof(configuration));
                if (_accountStorage != null)
                    if (configuration.AccountConnectionString != null)
                        await _accountStorage.ConnectAsync(configuration.AccountConnectionString);
            }
        }

        private async Task StartTcpServer()
        {
            if (_configurationProvider != null)
            {
                var configuration = await _configurationProvider.GetConfigurationAsync();
                if (configuration == null) throw new ArgumentNullException(nameof(configuration));
                if (configuration.RealmServerEndpoint != null)
                {
                    var endpoint = Parse(configuration.RealmServerEndpoint) ??
                                   throw new ArgumentNullException(
                                       $"IPEndPoint.Parse(configuration.RealmServerEndpoint)");
                    _tcpServer?.Start(endpoint, 10);
                }
            }
        }

        private void LogInitialInformation()
        {
            var assembly = GetExecutingAssembly();
            var assemblyTitle = assembly.GetCustomAttribute<AssemblyTitleAttribute>()?.Title;
            var product = assembly.GetCustomAttribute<AssemblyProductAttribute>()?.Product;
            var copyright = assembly.GetCustomAttribute<AssemblyCopyrightAttribute>()?.Copyright;

            if (assemblyTitle != null)
            {
                var version = GetExecutingAssembly().GetName().Version;
                if (version is { })
                    Title = $"{assemblyTitle} v{version}";
            }

            if (_logger == null) return;
            _logger.Debug(product);
            _logger.Debug(copyright);
            _logger.Message(@" __  __      _  _  ___  ___  ___               ");
            _logger.Message(@"|  \/  |__ _| \| |/ __|/ _ \/ __|   We Love    ");
            _logger.Message(@"| |\/| / _` | .` | (_ | (_) \__ \   Vanilla Wow");
            _logger.Message(@"|_|  |_\__,_|_|\_|\___|\___/|___/              ");
            _logger.Message("                                                ");
            _logger.Message("Website / Forum / Support: https://getmangos.eu/");
        }
    }
}
