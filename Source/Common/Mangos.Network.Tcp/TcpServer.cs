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
using System.Threading;
using System.Threading.Channels;
using Mangos.Loggers;
using Mangos.Network.Tcp.Extensions;
using static System.Net.Sockets.AddressFamily;
using static System.Net.Sockets.SocketFlags;
using static System.Net.Sockets.SocketType;

namespace Mangos.Network.Tcp
{
    public class TcpServer
    {
        private readonly ILogger _logger;
        private readonly ITcpClientFactory _tcpClientFactory;
        private readonly CancellationTokenSource _cancellationTokenSource;

        private Socket _socket;

        public TcpServer(ILogger logger, ITcpClientFactory tcpClientFactory)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _tcpClientFactory = tcpClientFactory ?? throw new ArgumentNullException(nameof(tcpClientFactory));
            _cancellationTokenSource = new CancellationTokenSource();
        }

        public void Start(IPEndPoint endPoint, int backlog)
        {
            if (endPoint == null) throw new ArgumentNullException(nameof(endPoint));
            if (backlog <= 0) throw new ArgumentOutOfRangeException(nameof(backlog));
            if (_socket != null)
            {
                _logger?.Error("TcpServer already started");
                throw new Exception("TcpServer already started");
            }
            try
            {
                _socket = new Socket(InterNetwork, Stream, ProtocolType.Tcp);
                _socket.Bind(endPoint);
                _socket.Listen(backlog);
                StartAcceptLoop();
                _logger?.Debug("TcpServer has been started");
            }
            catch (Exception ex)
            {
                _logger?.Error("TcpServer start execption", ex);
                throw;
            }
        }

        private async void StartAcceptLoop()
        {
            try
            {
                _logger?.Debug("Start accepting connections");
                while (_cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested)
                {
                    if (_socket != null) OnAcceptAsync(await _socket.AcceptAsync());
                }
            }
            catch (Exception ex)
            {
                _logger?.Error("Error during accepting conenction", ex);
            }
        }

        private async void OnAcceptAsync(Socket clientSocket)
        {
            if (clientSocket == null) throw new ArgumentNullException(nameof(clientSocket));
            try
            {
                var tcpClient = await _tcpClientFactory.CreateTcpClientAsync(clientSocket);
                if (tcpClient == null) throw new ArgumentNullException(nameof(tcpClient));
                var recieveChannel = Channel.CreateUnbounded<byte>() ?? throw new ArgumentNullException(nameof(Channel.CreateUnbounded));
                var sendChannel = Channel.CreateUnbounded<byte>() ?? throw new ArgumentNullException(nameof(Channel.CreateUnbounded));

                if (recieveChannel.Writer != null)
                {
                    RecieveAsync(clientSocket, recieveChannel.Writer);
                    if (sendChannel.Reader != null)
                    {
                        SendAsync(clientSocket, sendChannel.Reader);
                        if (_cancellationTokenSource != null)
                            tcpClient.HandleAsync(recieveChannel.Reader, sendChannel.Writer,
                                _cancellationTokenSource.Token);
                    }
                }

                _logger?.Debug("New Tcp conenction established");
            }
            catch (Exception ex)
            {
                _logger?.Error("Error during accepting conenction handler", ex);
            }
        }


        private async void RecieveAsync(Socket client, ChannelWriter<byte> writer)
        {
            if (client == null) throw new ArgumentNullException(nameof(client));
            if (writer == null) throw new ArgumentNullException(nameof(writer));
            try
            {
                var buffer = new byte[client.ReceiveBufferSize];
                while (_cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested)
                {
                    var bytesRead = await client.ReceiveAsync(buffer, None);
                    if (bytesRead == 0)
                    {
                        client.Dispose();
                        return;
                    }
                    await writer.WriteAsync(buffer, bytesRead);
                }
            }
            catch (Exception ex)
            {
                _logger?.Error("Error during recieving data from socket", ex);
            }
        }

        private async void SendAsync(Socket client, ChannelReader<byte> reader)
        {
            if (client == null) throw new ArgumentNullException(nameof(client));
            if (reader == null) throw new ArgumentNullException(nameof(reader));
            try
            {
                var buffer = new byte[client.SendBufferSize];
                while (_cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested)
                {
                    await reader.WaitToReadAsync();
                    var writeCount = 0;
                    if (buffer.Length > writeCount)
                        for (writeCount = 0;
                            writeCount < buffer.Length && reader.TryRead(out buffer[writeCount]);
                            writeCount++)
                        {
                        }

                    var arraySegment = new ArraySegment<byte>(buffer, 0, writeCount);
                    await client.SendAsync(arraySegment, None);
                }
            }
            catch (Exception ex)
            {
                _logger?.Error("Error during sending data to socket", ex);
            }
        }
    }
}
