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
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Mangos.Common.Globals;
using Mangos.Loggers;
using Mangos.Network.Tcp;
using Mangos.Storage.Account;

namespace Mangos.Realm.Factories
{
    public class RealmServerClientFactory : ITcpClientFactory
    {
        private readonly ILogger _logger;
        private readonly IAccountStorage _accountStorage;
        private readonly Converter _converter;
        private readonly MangosGlobalConstants _mangosGlobalConstants;

        public RealmServerClientFactory(ILogger logger,
            IAccountStorage accountStorage,
            Converter converter,
            MangosGlobalConstants mangosGlobalConstants)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _accountStorage = accountStorage ?? throw new ArgumentNullException(nameof(accountStorage));
            _converter = converter ?? throw new ArgumentNullException(nameof(converter));
            _mangosGlobalConstants = mangosGlobalConstants ?? throw new ArgumentNullException(nameof(mangosGlobalConstants));
        }

        public async Task<ITcpClient> CreateTcpClientAsync(Socket clientSocket)
        {
            if (clientSocket == null) throw new ArgumentNullException(nameof(clientSocket));
            if (_logger == null) throw new ArgumentNullException(nameof(_logger));
            if (_accountStorage == null) throw new ArgumentNullException(nameof(_accountStorage));
            if (_converter == null) throw new ArgumentNullException(nameof(_converter));
            if (_mangosGlobalConstants == null) throw new ArgumentNullException(nameof(_mangosGlobalConstants));
            if (clientSocket.RemoteEndPoint != null)
                return new RealmServerClient(
                    _logger,
                    _accountStorage,
                    _converter,
                    _mangosGlobalConstants,
                    clientSocket.RemoteEndPoint as IPEndPoint);
            return null;
        }
    }
}
