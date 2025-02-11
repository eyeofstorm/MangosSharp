//
// Copyright (C) 2013-2023 getMaNGOS <https://getmangos.eu>
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

using Mangos.Cluster.Globals;
using Mangos.Cluster.Handlers;
using Mangos.Common.Enums.Authentication;
using Mangos.Common.Enums.Global;
using Mangos.Common.Globals;
using Mangos.Common.Legacy;
using Mangos.Configuration;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Mangos.Cluster.Network;

public class ClientClass : ClientInfo
{
    private readonly MangosConfiguration mangosConfiguration;
    private readonly ClusterServiceLocator _clusterServiceLocator;

    public Client Client { get; } = new();

    public ClientClass(
        ClusterServiceLocator clusterServiceLocator,
        MangosConfiguration mangosConfiguration)
    {
        _clusterServiceLocator = clusterServiceLocator;
        this.mangosConfiguration = mangosConfiguration;
    }

    public Socket Socket { get; set; }
    public WcHandlerCharacter.CharacterObject Character;

    public ClientInfo GetClientInfo()
    {
        ClientInfo ci = new()
        {
            Access = Access,
            Account = Account,
            Index = Index,
            IP = IP,
            Port = Port
        };
        return ci;
    }

    public Task OnConnectAsync()
    {
        if (Socket is null)
        {
            throw new ApplicationException("socket doesn't exist!");
        }

        if (_clusterServiceLocator.WorldCluster.ClienTs is null)
        {
            throw new ApplicationException("Clients doesn't exist!");
        }

        IPEndPoint remoteEndPoint = (IPEndPoint)Socket.RemoteEndPoint;
        IP = remoteEndPoint.Address.ToString();
        Port = (uint)remoteEndPoint.Port;

        // DONE: Connection spam protection
        if (_clusterServiceLocator.WcNetwork.LastConnections.ContainsKey(_clusterServiceLocator.WcNetwork.Ip2Int(IP)))
        {
            if (DateTime.Now > _clusterServiceLocator.WcNetwork.LastConnections[_clusterServiceLocator.WcNetwork.Ip2Int(IP)])
            {
                _clusterServiceLocator.WcNetwork.LastConnections[_clusterServiceLocator.WcNetwork.Ip2Int(IP)] = DateTime.Now.AddSeconds(5d);
            }
            else
            {
                Socket.Close();
                Dispose();
                return Task.CompletedTask;
            }
        }
        else
        {
            _clusterServiceLocator.WcNetwork.LastConnections.Add(_clusterServiceLocator.WcNetwork.Ip2Int(IP), DateTime.Now.AddSeconds(5d));
        }

        _clusterServiceLocator.WorldCluster.Log.WriteLine(LogType.DEBUG, "Incoming connection from [{0}:{1}]", IP, Port);

        // Send Auth Challenge
        PacketClass p = new(Opcodes.SMSG_AUTH_CHALLENGE);
        p.AddInt32((int)Index);
        Send(p);
        Index = (uint)Interlocked.Increment(ref _clusterServiceLocator.WorldCluster.ClietniDs);
        lock (((ICollection)_clusterServiceLocator.WorldCluster.ClienTs).SyncRoot)
        {
            _clusterServiceLocator.WorldCluster.ClienTs.Add(Index, this);
        }

        return Task.CompletedTask;
    }

    public void OnPacket(PacketClass p)
    {
        if (Socket is null)
        {
            throw new ApplicationException("socket is Null!");
        }

        if (_clusterServiceLocator.WorldCluster.ClienTs is null)
        {
            throw new ApplicationException("Clients doesn't exist!");
        }

        if (_clusterServiceLocator.WorldCluster.GetPacketHandlers() is null)
        {
            throw new ApplicationException("PacketHandler is empty!");
        }

        var client = this;

        if (!_clusterServiceLocator.WorldCluster.GetPacketHandlers().ContainsKey(p.OpCode))
        {
            if (Character is null || !Character.IsInWorld)
            {
                Socket?.Dispose();
                Socket?.Close();

                _clusterServiceLocator.WorldCluster.Log.WriteLine(LogType.WARNING, "[{0}:{1}] Unknown Opcode 0x{2:X} [{2}], DataLen={4}", IP, Port, p.OpCode, Environment.NewLine, p.Length);
                _clusterServiceLocator.Packets.DumpPacket(p.Data, client);
            }
            else
            {
                try
                {
                    Character.GetWorld.ClientPacket(Index, p.Data);
                }
                catch
                {
                    _clusterServiceLocator.WcNetwork.WorldServer.Disconnect("NULL", new List<uint> { Character.Map });
                }
            }
        }
        else
        {
            try
            {
                _clusterServiceLocator.WorldCluster.GetPacketHandlers()[p.OpCode].Invoke(p, client);
            }
            catch (Exception e)
            {
                _clusterServiceLocator.WorldCluster.Log.WriteLine(LogType.FAILED, "Opcode handler {2}:{2:X} caused an error: {1}{0}", e.ToString(), Environment.NewLine, p.OpCode);
            }
        }
    }

    public void Send(byte[] data)
    {
        if (!Socket.Connected)
        {
            return;
        }

        try
        {
            if (Client.PacketEncryption.IsEncryptionEnabled)
            {
                Encode(data);
            }

            Socket.BeginSend(data, 0, data.Length, SocketFlags.None, OnSendComplete, null);
        }
        catch (Exception err)
        {
            // NOTE: If it's a error here it means the connection is closed?
            _clusterServiceLocator.WorldCluster.Log.WriteLine(LogType.CRITICAL, "Connection from [{0}:{1}] caused an error {2}{3}", IP, Port, err.ToString(), Environment.NewLine);
            Delete();
        }
    }

    public void Send(PacketClass packet)
    {
        if (packet == null)
        {
            throw new ApplicationException("Packet doesn't contain data!");
        }

        if (Socket == null)
        {
            return;
        }

        if (!Socket.Connected)
        {
            return;
        }

        using (packet)
        {
            try
            {
                var data = packet.Data;
                if (Client.PacketEncryption.IsEncryptionEnabled)
                {
                    Encode(data);
                }

                Socket.BeginSend(data, 0, data.Length, SocketFlags.None, OnSendComplete, null);
            }
            catch (Exception err)
            {
                // NOTE: If it's a error here it means the connection is closed?
                _clusterServiceLocator.WorldCluster.Log.WriteLine(LogType.CRITICAL, "Connection from [{0}:{1}] caused an error {2}{3}", IP, Port, err.ToString(), Environment.NewLine);
                Delete();
            }
        }
    }

    public void SendMultiplyPackets(PacketClass packet)
    {
        if (packet is null)
        {
            throw new ApplicationException("Packet doesn't contain data!");
        }

        if (!Socket.Connected)
        {
            return;
        }

        try
        {
            var data = (byte[])packet.Data.Clone();

            if (Client.PacketEncryption.IsEncryptionEnabled)
            {
                Encode(data);
            }

            Socket.BeginSend(data, 0, data.Length, SocketFlags.None, OnSendComplete, null);
        }
        catch (Exception err)
        {
            // NOTE: If it's a error here it means the connection is closed?
            _clusterServiceLocator.WorldCluster.Log.WriteLine(LogType.CRITICAL, "Connection from [{0}:{1}] caused an error {2}{3}", IP, Port, err.ToString(), Environment.NewLine);
            Delete();
        }

        // Don't forget to clean after using this function
    }

    public void OnSendComplete(IAsyncResult ar)
    {
        if (Socket is not null)
        {
            var bytesSent = Socket.EndSend(ar);
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

            Socket?.Close();

            lock (((ICollection)_clusterServiceLocator.WorldCluster.ClienTs).SyncRoot)
            {
                _clusterServiceLocator.WorldCluster.ClienTs.Remove(Index);
            }

            if (Character is not null)
            {
                if (Character.IsInWorld)
                {
                    Character.IsInWorld = false;
                    Character.GetWorld.ClientDisconnect(Index);
                }

                Character.Dispose();
            }

            Character = null;
        }

        _disposedValue = true;
    }

    // This code added by Visual Basic to correctly implement the disposable pattern.
    public void Dispose()
    {
        // Do not change this code.  Put cleanup code in Dispose(ByVal disposing As Boolean) above.
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    public void Delete()
    {
        Socket.Close();
        Dispose();
    }

    public void Encode(byte[] data)
    {
        var key = Client.PacketEncryption.Key;

        for (var i = 0; i < 4; i++)
        {
            data[i] = (byte)(((Client.PacketEncryption.Hash[key[3]] ^ data[i]) + key[2]) % 256);
            key[2] = data[i];
            key[3] = (byte)((key[3] + 1) % 40);
        }
    }

    public void EnQueue(object state)
    {
        while (_clusterServiceLocator.WorldCluster.CharacteRs.Count > mangosConfiguration.Cluster.ServerPlayerLimit)
        {
            if (!Socket.Connected)
            {
                return;
            }

            new PacketClass(Opcodes.SMSG_AUTH_RESPONSE).AddInt8((byte)LoginResponse.LOGIN_WAIT_QUEUE);
            new PacketClass(Opcodes.SMSG_AUTH_RESPONSE).AddInt32(_clusterServiceLocator.WorldCluster.ClienTs.Count - _clusterServiceLocator.WorldCluster.CharacteRs.Count);            // amount of players in queue
            Send(new PacketClass(Opcodes.SMSG_AUTH_RESPONSE));
            _clusterServiceLocator.WorldCluster.Log.WriteLine(LogType.INFORMATION, "[{1}:{2}] AUTH_WAIT_QUEUE: Server player limit reached!", IP, Port);
            Thread.Sleep(6000);
        }

        var argclient = this;
        _clusterServiceLocator.WcHandlersAuth.SendLoginOk(argclient);
    }
}
