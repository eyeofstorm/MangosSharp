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
using System.Collections;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Mangos.Cluster.Globals;
using Mangos.Cluster.Handlers;
using Mangos.Common.Enums.Authentication;
using Mangos.Common.Enums.Global;
using Mangos.Common.Globals;
using Mangos.Common.Legacy;
using Mangos.Network.Tcp;
using Mangos.Network.Tcp.Extensions;
using Microsoft.VisualBasic;
using static System.GC;
using static System.Net.Sockets.SocketFlags;
using static System.Threading.Interlocked;
using static System.Threading.Thread;

namespace Mangos.Cluster.Network
{
    public class ClientClass : ClientInfo, ITcpClient
    {
        private readonly ClusterServiceLocator _clusterServiceLocator;

        public ClientClass(ClusterServiceLocator clusterServiceLocator, Socket socket)
        {
            _clusterServiceLocator = clusterServiceLocator;
            _socket = socket;
        }

        private readonly Socket _socket;
        public WcHandlerCharacter.CharacterObject Character;
        public byte[] SsHash;
        public bool Encryption = false;
        private readonly byte[] _key = { 0, 0, 0, 0 };

        public ClientInfo GetClientInfo()
        {
            var ci = new ClientInfo
            {
                Access = Access,
                Account = Account,
                Index = Index,
                IP = IP,
                Port = Port
            };
            return ci;
        }

        public async Task  OnConnectAsync()
        {
            if (_socket is null)
                throw new ApplicationException("socket doesn't exist!");
            if (_clusterServiceLocator.WorldCluster.ClienTs is null)
                throw new ApplicationException("Clients doesn't exist!");
            if (_socket.RemoteEndPoint != null)
            {
                var remoteEndPoint = _socket.RemoteEndPoint as IPEndPoint;
                if (remoteEndPoint?.Address != null) IP = remoteEndPoint.Address.ToString();
                if (remoteEndPoint != null) Port = (uint) remoteEndPoint.Port;
            }

            // DONE: Connection spam protection
            if (IP != null && _clusterServiceLocator.WcNetwork?.LastConnections?.ContainsKey(_clusterServiceLocator.WcNetwork.Ip2Int(IP)) == true)
            {
                if (DateTime.Now > _clusterServiceLocator.WcNetwork.LastConnections[_clusterServiceLocator.WcNetwork.Ip2Int(IP)])
                {
                    _clusterServiceLocator.WcNetwork.LastConnections[_clusterServiceLocator.WcNetwork.Ip2Int(IP)] = DateTime.Now.AddSeconds(5d);
                }
                else
                {
                    _socket.Close();
                    Dispose();
                    return;
                }
            }
            else
            {
                if (_clusterServiceLocator.WcNetwork != null)
                {
                    if (IP != null)
                    {
                        var i = _clusterServiceLocator.WcNetwork.Ip2Int(IP);
                        if (_clusterServiceLocator.WcNetwork?.LastConnections != null && !(_clusterServiceLocator.WcNetwork?.LastConnections).ContainsKey(i))
                            _clusterServiceLocator.WcNetwork?.LastConnections?.Add(i, DateTime.Now.AddSeconds(5d));
                    }
                }
            }

            if (_clusterServiceLocator != null)
            {
                if (IP != null)
                    _clusterServiceLocator.WorldCluster.Log?.WriteLine(LogType.DEBUG,
                        "Incoming connection from [{0}:{1}]",
                        IP, Port);

                // Send Auth Challenge
                using var p = new PacketClass(Opcodes.SMSG_AUTH_CHALLENGE);
                p.AddInt32((int) Index);
                Send(p);

                Index = (uint) Increment(ref _clusterServiceLocator.WorldCluster.ClietniDs);
                var root = (_clusterServiceLocator.WorldCluster.ClienTs as ICollection).SyncRoot;
                var syncRoot = root;
                lock (syncRoot)
                {
                    if (!_clusterServiceLocator.WorldCluster.ClienTs.ContainsKey(Index))
                        _clusterServiceLocator.WorldCluster.ClienTs?.Add(Index, this);
                }

                _clusterServiceLocator?.WcStats?.ConnectionsIncrement();
            }
        }

        public async void HandleAsync(ChannelReader<byte> reader, ChannelWriter<byte> writer, CancellationToken cancellationToken)
        {
            var buffer = new byte[8192];
            while (!cancellationToken.IsCancellationRequested)
            {
                if (reader != null)
                {
                    await reader.ReadAsync(buffer, 0, 6);
                    if (Encryption)
                    {
                        Decode(buffer);
                    }
                    var length = buffer[1] + buffer[0] * 256 + 2;
                    await reader.ReadAsync(buffer, 6, length - 6);
                }

                using var packet = new PacketClass(buffer);
                OnPacket(packet);
            }
        }

        public void OnPacket(PacketClass p)
        {
            if (p == null) throw new ArgumentNullException(nameof(p));
            if (_socket is null)
                throw new ApplicationException("socket is Null!");
            if (_clusterServiceLocator.WorldCluster.ClienTs is null)
                throw new ApplicationException("Clients doesn't exist!");
            if (_clusterServiceLocator.WorldCluster.GetPacketHandlers() is null)
                throw new ApplicationException("PacketHandler is empty!");

            var client = this;

            if (_clusterServiceLocator.WorldCluster.GetConfig().PacketLogging)
            {
                if (p.Data != null) _clusterServiceLocator.Packets?.LogPacket(p.Data, false, client);
            }

            if (!_clusterServiceLocator.WorldCluster.GetPacketHandlers().ContainsKey(p.OpCode))
            {
                if (Character is null || !Character.IsInWorld)
                {
                    _socket?.Dispose();
                    _socket?.Close();

                    _clusterServiceLocator?.WorldCluster.Log.WriteLine(LogType.WARNING,
                        "[{0}:{1}] Unknown Opcode 0x{2:X} [{2}], DataLen={4}", IP, Port, p.OpCode, Constants.vbCrLf,
                        p.Length);
                    if (p.Data != null) _clusterServiceLocator?.Packets?.DumpPacket(p.Data, client);
                }
                else
                {
                    try
                    {
                        if (p.Data != null) Character?.GetWorld?.ClientPacket(Index, p.Data);
                    }
                    catch
                    {
                        _clusterServiceLocator.WcNetwork?.WorldServer?.Disconnect("NULL",
                            new List<uint> {Character.Map});
                    }
                }
            }
            else
            {
                try
                {
                    var packets = _clusterServiceLocator.WorldCluster.GetPacketHandlers();
                    if (packets != null && packets.ContainsKey(p.OpCode)) packets[p.OpCode].Invoke(p, client);
                }
                catch (Exception e)
                {
                    _clusterServiceLocator.WorldCluster.Log?.WriteLine(LogType.FAILED,
                        "Opcode handler {2}:{2:X} caused an error: {1}{0}", e.ToString(), Constants.vbCrLf,
                        p.OpCode);
                }
            }
        }

        public void Send(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (!_socket.Connected)
                return;
            try
            {
                if (_clusterServiceLocator.WorldCluster != null && _clusterServiceLocator != null && _clusterServiceLocator.WorldCluster.GetConfig().PacketLogging)
                {
                    var argclient = this;
                    _clusterServiceLocator.Packets?.LogPacket(data, true, argclient);
                }

                if (Encryption)
                    Encode(data);
                _socket?.BeginSend(data, 0, data.Length, None, OnSendComplete, null);
            }
            catch (Exception err)
            {
                // NOTE: If it's a error here it means the connection is closed?
                _clusterServiceLocator?.WorldCluster?.Log?.WriteLine(LogType.CRITICAL,
                    "Connection from [{0}:{1}] caused an error {2}{3}", IP, Port, err.ToString(), Constants.vbCrLf);
                Delete();
            }
        }

        public void Send(PacketClass packet)
        {
            if (packet == null)
                throw new ApplicationException("Packet doesn't contain data!");
            if (_socket == null)
                return;
            if (!_socket.Connected)
                return;

            using var @class = packet;
            try
            {
                if (packet.Data == null) return;
                var data = packet.Data ?? throw new ArgumentNullException(nameof(packet));
                if (_clusterServiceLocator.WorldCluster != null && _clusterServiceLocator != null && _clusterServiceLocator.WorldCluster.GetConfig().PacketLogging)
                {
                    var argclient = this;
                    _clusterServiceLocator.Packets?.LogPacket(data, true, argclient);
                }

                if (Encryption)
                    Encode(data);

                _socket.BeginSend(data, 0, data.Length, None, OnSendComplete, null);
            }
            catch (Exception err)
            {
                // NOTE: If it's a error here it means the connection is closed?
                if (IP != null)
                    _clusterServiceLocator?.WorldCluster?.Log?.WriteLine(LogType.CRITICAL,
                        "Connection from [{0}:{1}] caused an error {2}{3}", IP, Port, err.ToString(), Constants.vbCrLf);
                Delete();
            }
        }

        public void SendMultiplyPackets(PacketClass packet)
        {
            if (packet is null)
                throw new ApplicationException("Packet doesn't contain data!");
            if (!_socket.Connected)
                return;
            try
            {
                if (packet.Data != null)
                {
                    var data = packet.Data.Clone() as byte[];
                    var logging = _clusterServiceLocator?.WorldCluster?.GetConfig().PacketLogging;
                    var packetLogging = logging;
                    if (packetLogging != null && packetLogging == true)
                    {
                        var argclient = this;
                        _clusterServiceLocator.Packets?.LogPacket(data, true, argclient);
                    }

                    if (Encryption && data != null) Encode(data);
                    if (data != null) _socket?.BeginSend(data, 0, data.Length, None, OnSendComplete, null);
                }
            }
            catch (Exception err)
            {
                // NOTE: If it's a error here it means the connection is closed?
                _clusterServiceLocator?.WorldCluster?.Log.WriteLine(LogType.CRITICAL, "Connection from [{0}:{1}] caused an error {2}{3}", IP, Port, err.ToString(), Constants.vbCrLf);
                Delete();
            }

            // Don't forget to clean after using this function
            packet.Dispose();
        }

        public void OnSendComplete(IAsyncResult ar)
        {
            if (_socket == null) return;
            if (ar == null) return;
            var bytesSent = _socket.EndSend(ar);
            if (_clusterServiceLocator?.WcStats != null)
            {
                Add(ref _clusterServiceLocator.WcStats.DataTransferOut, bytesSent);
            }
        }

        private bool _disposedValue; // To detect redundant calls

        // IDisposable
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                // TODO: free unmanaged resources (unmanaged objects) and override Finalize() below.
                // TODO: set large fields to null.

                // On Error Resume Next
                // May have to trap and use exception handler rather than the on error resume next rubbish

                _socket?.Close();
                if (_clusterServiceLocator != null)
                {
                    var syncRoot = (_clusterServiceLocator.WorldCluster?.ClienTs as ICollection)?.SyncRoot;
                    if (syncRoot != null)
                        lock (syncRoot)
                        {
                            if ((_clusterServiceLocator.WorldCluster?.ClienTs).ContainsKey(Index))
                                _clusterServiceLocator.WorldCluster?.ClienTs?.Remove(Index);
                        }

                    if (Character != null && !(Character is { IsInWorld: true }))
                    {
                        Character.IsInWorld = false;
                        Character.GetWorld.ClientDisconnect(Index);
                    }

                    Character?.Dispose();

                    Character = null;
                    _clusterServiceLocator.WcStats?.ConnectionsDecrement();
                }
            }

            _disposedValue = true;
        }

        public void Dispose()
        {
            // Do not change this code.  Put cleanup code in Dispose(ByVal disposing As Boolean) above.
            Dispose(true);
            SuppressFinalize(this);
        }

        public void Delete()
        {
            _socket?.Close();
            Dispose();
        }

        public void Decode(byte[] data)
        {
            for (var i = 0; i < 6; i++)
            {
                var tmp = data[i];
                if (i >= 0 && data.Length > i)
                    if (SsHash != null)
                        if (_key != null)
                            data[i] = (byte) (SsHash[_key[1]] ^ (256 + data[i] - _key[0]) % 256);
                if (_key == null) continue;
                _key[0] = tmp;
                _key[1] = (byte) ((_key[1] + 1) % 40);
            }
        }

        public void Encode(byte[] data)
        {
            for (var i = 0; i < 4; i++)
            {
                if (data != null)
                {
                    if (SsHash != null)
                        if (_key != null)
                            data[i] = (byte) (((SsHash[_key[3]] ^ data[i]) + _key[2]) % 256);
                    if (_key != null) _key[2] = data[i];
                }

                if (_key != null) _key[3] = (byte) ((_key[3] + 1) % 40);
            }
        }

        public void EnQueue(object state)
        {
            while (_clusterServiceLocator.WorldCluster.CharacteRs.Count > _clusterServiceLocator.WorldCluster.GetConfig().ServerPlayerLimit)
            {
                if (_socket != null && !_socket.Connected)
                    return;
                new PacketClass(Opcodes.SMSG_AUTH_RESPONSE).AddInt8((byte)LoginResponse.LOGIN_WAIT_QUEUE);
                new PacketClass(Opcodes.SMSG_AUTH_RESPONSE).AddInt32(_clusterServiceLocator.WorldCluster.ClienTs.Count - _clusterServiceLocator.WorldCluster.CharacteRs.Count);            // amount of players in queue
                Send(new PacketClass(Opcodes.SMSG_AUTH_RESPONSE));
                _clusterServiceLocator.WorldCluster.Log.WriteLine(LogType.INFORMATION, "[{1}:{2}] AUTH_WAIT_QUEUE: Server player limit reached!", IP, Port);
                Sleep(6000);
            }

            var clientele = this;
            _clusterServiceLocator.WcHandlersAuth?.SendLoginOk(clientele);
        }
    }
}