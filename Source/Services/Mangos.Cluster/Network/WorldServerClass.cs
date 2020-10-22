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
using System.Linq;
using System.Threading;
using Mangos.Cluster.Globals;
using Mangos.Common.Enums.Chat;
using Mangos.Common.Enums.Global;
using Mangos.Common.Legacy;
using Microsoft.AspNetCore.SignalR;
using static System.Math;
using static Mangos.Common.Globals.Opcodes;
using static Mangos.SignalR.ProxyClient;

namespace Mangos.Cluster.Network
{
    public class WorldServerClass : Hub, ICluster
    {
        private readonly ClusterServiceLocator _clusterServiceLocator;

        public bool MFlagStopListen = false;
        private Timer _mTimerPing;
        private Timer _mTimerStats;
        private Timer _mTimerCpu;

        public WorldServerClass(ClusterServiceLocator clusterServiceLocator)
        {
            _clusterServiceLocator = clusterServiceLocator ?? throw new ArgumentNullException(nameof(clusterServiceLocator));
        }

        public void Start()
        {
            // Creating ping timer
            _mTimerPing = new Timer(Ping, null, 0, 15000);

            // Creating stats timer
            if (_clusterServiceLocator.WorldCluster != null && _clusterServiceLocator != null && _clusterServiceLocator.WorldCluster.GetConfig().StatsEnabled)
            {
                if (_clusterServiceLocator.WcStats != null)
                    _mTimerStats = new Timer(_clusterServiceLocator.WcStats.GenerateStats, null,
                        _clusterServiceLocator.WorldCluster.GetConfig().StatsTimer,
                        _clusterServiceLocator.WorldCluster.GetConfig().StatsTimer);
            }

            // Creating CPU check timer
            if (_clusterServiceLocator?.WcStats != null)
                _mTimerCpu = new Timer(_clusterServiceLocator.WcStats.CheckCpu, null, 1000, 1000);
        }

        public Dictionary<uint, IWorld> Worlds = new Dictionary<uint, IWorld>();
        public Dictionary<uint, WorldInfo> WorldsInfo = new Dictionary<uint, WorldInfo>();

        public bool Connect(string uri, List<uint> maps)
        {
            if (uri == null) throw new ArgumentNullException(nameof(uri));
            if (maps == null) throw new ArgumentNullException(nameof(maps));
            if (maps.Count == 0) throw new ArgumentException("Value cannot be an empty collection.", nameof(maps));
            try
            {
                Disconnect(uri, maps);
                var worldServerInfo = new WorldInfo();
                _clusterServiceLocator?.WorldCluster?.Log?.WriteLine(LogType.INFORMATION,
                    "Connected Map Server: {0}",
                    uri);
                var syncRoot = (Worlds as ICollection)?.SyncRoot;
                if (syncRoot != null)
                    lock (syncRoot)
                    {
                        foreach (var map in maps)
                        {
                            // NOTE: Password protected remoting
                            if (Worlds != null) Worlds[map] = Create<IWorld>(uri);
                            if (WorldsInfo != null) WorldsInfo[map] = worldServerInfo;
                        }
                    }
            }
            catch (Exception ex)
            {
                _clusterServiceLocator?.WorldCluster?.Log?.WriteLine(LogType.CRITICAL, "Unable to reverse connect. [{0}]", ex.ToString());
                return false;
            }

            return true;
        }

        public void Disconnect(string uri, List<uint> maps)
        {
            if (uri == null) throw new ArgumentNullException(nameof(uri));
            if (maps == null) throw new ArgumentNullException(nameof(maps));
            switch (maps.Count)
            {
                case 0:
                {
                    return;
                }
            }

            // TODO: Unload arenas or battlegrounds that is hosted on this server!
            foreach (var map in maps)
            {

                // DONE: Disconnecting clients
                if (_clusterServiceLocator?.WorldCluster == null) continue;
                if (_clusterServiceLocator.WorldCluster.ClienTs != null)
                {
                    var syncRoot = (_clusterServiceLocator.WorldCluster.ClienTs as ICollection).SyncRoot;
                    lock (syncRoot)
                    {
                        foreach (var value in _clusterServiceLocator.WorldCluster.ClienTs.Cast<ClientClass>().Where(
                            value =>
                            {
                                if (value == null) throw new ArgumentNullException(nameof(value));
                                return value.Character != null && value.Character.IsInWorld &&
                                       value.Character.Map == map;
                            }))
                        {
                            if (value == null) continue;
                            value.Send(new PacketClass(SMSG_LOGOUT_COMPLETE));
                            new PacketClass(SMSG_LOGOUT_COMPLETE).Dispose();
                            value.Character?.Dispose();
                            value.Character = null;
                        }
                    }
                }

                if (Worlds == null) continue;
                {
                    var root = (Worlds as ICollection)?.SyncRoot;
                    {
                        lock (root)
                        {
                            if (Worlds != null && !Worlds.ContainsKey(map)) continue;
                        }

                        try
                        {
                            if (Worlds != null)
                            {
                                    if (Worlds.ContainsKey(map)) Worlds[map] = default;
                            }

                            if (WorldsInfo != null) WorldsInfo[map] = null;
                        }
                        finally
                        {
                            var syncRoot = root;
                            lock (syncRoot)
                            {
                                if (Worlds.ContainsKey(map)) Worlds.Remove(map);
                                if (WorldsInfo != null && WorldsInfo.ContainsKey(map)) WorldsInfo?.Remove(map);
                                _clusterServiceLocator?.WorldCluster.Log?.WriteLine(LogType.INFORMATION,
                                    "Map: {0:000} has been disconnected!", map);
                            }
                        }
                    }
                }
            }
        }

        public void Ping(object state)
        {
            //if (state == null) throw new ArgumentNullException(nameof(state));
            var downedServers = new List<uint>();
            var sentPingTo = new Dictionary<WorldInfo, int>();

            // Ping WorldServers
            var syncRoot = (Worlds as ICollection)?.SyncRoot;
            if (syncRoot != null)
                lock (syncRoot)
                    if (Worlds != null && WorldsInfo != null)
                        foreach (var (key, value) in Worlds)
                            try
                            {
                                if (!WorldsInfo.ContainsKey(key)) continue;
                                if (!sentPingTo.ContainsKey(WorldsInfo[key]))
                                {
                                    if (_clusterServiceLocator != null)
                                    {
                                        var myTime = _clusterServiceLocator.NativeMethods.timeGetTime("");
                                        if (value == null) continue;
                                        if (WorldsInfo.ContainsKey(key)) value.Ping(myTime, WorldsInfo[key].Latency);
                                        var latency =
                                            Abs(myTime - _clusterServiceLocator.NativeMethods.timeGetTime(""));
                                        if (WorldsInfo.ContainsKey(key)) WorldsInfo[key].Latency = latency;
                                        if (sentPingTo.ContainsKey(WorldsInfo[key]))
                                            sentPingTo[WorldsInfo[key]] = latency;
                                        _clusterServiceLocator.WorldCluster.Log.WriteLine(LogType.NETWORK,
                                            "Map {0:000} ping: {1}ms", key, latency);
                                    }

                                    // Query CPU and Memory usage
                                    var serverInfo = value.GetServerInfo() ??
                                                     throw new ArgumentNullException(nameof(state));
                                    if (WorldsInfo.ContainsKey(key)) serverInfo.cpuUsage = WorldsInfo[key].CpuUsage;
                                    if (WorldsInfo.ContainsKey(key))
                                        serverInfo.memoryUsage = WorldsInfo[key].MemoryUsage;
                                }
                                else
                                {
                                    if (sentPingTo.ContainsKey(WorldsInfo[key]))
                                        _clusterServiceLocator?.WorldCluster.Log.WriteLine(LogType.NETWORK,
                                            "Map {0:000} ping: {1}ms", key, sentPingTo[WorldsInfo[key]]);
                                }
                            }
                            catch
                            {
                                _clusterServiceLocator?.WorldCluster.Log.WriteLine(LogType.WARNING,
                                    "Map {0:000} is currently down!", key);
                                downedServers.Add(key);
                            }

            // Notification message
            if (Worlds != null && Worlds.Count == 0)
                _clusterServiceLocator?.WorldCluster.Log.WriteLine(LogType.WARNING,
                    "No maps are currently available!");

            // Drop WorldServers
            Disconnect("NULL", downedServers);
        }

        public void ClientSend(uint id, byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (data.Length == 0) throw new ArgumentException("Value cannot be an empty collection.", nameof(data));
            if (_clusterServiceLocator.WorldCluster.ClienTs != null && _clusterServiceLocator.WorldCluster != null &&
                _clusterServiceLocator != null && _clusterServiceLocator.WorldCluster.ClienTs.ContainsKey(id))
                _clusterServiceLocator.WorldCluster.ClienTs[id].Send(data);
        }

        public void ClientDrop(uint id)
        {
            if (_clusterServiceLocator.WorldCluster.ClienTs != null && _clusterServiceLocator.WorldCluster != null &&
                _clusterServiceLocator != null && _clusterServiceLocator.WorldCluster.ClienTs.ContainsKey(id))
                try
                {
                    if (_clusterServiceLocator.WorldCluster.ClienTs.ContainsKey(id))
                    {
                        var o = _clusterServiceLocator.WorldCluster.ClienTs[id].Character;
                        if (o != null)
                        {
                            var character = o;
                            using var characterObject = character;
                            _clusterServiceLocator.WorldCluster.Log?.WriteLine(LogType.INFORMATION,
                                "[{0:000000}] Client has dropped map {1:000}", id,
                                characterObject.Map);
                        }
                    }

                    _clusterServiceLocator.WorldCluster.ClienTs[id].Character.IsInWorld = false;
                    _clusterServiceLocator.WorldCluster.ClienTs[id].Character.OnLogout();
                }
                catch (Exception ex)
                {
                    _clusterServiceLocator.WorldCluster.Log?.WriteLine(LogType.INFORMATION,
                        "[{0:000000}] Client has dropped an exception: {1}", id, ex.ToString());
                }
            else
            {
                _clusterServiceLocator.WorldCluster.Log?.WriteLine(LogType.INFORMATION,
                    "[{0:000000}] Client connection has been lost.", id);
            }
        }

        public void ClientTransfer(uint id, float posX, float posY, float posZ, float ori, uint map)
        {
            if (map <= 0) throw new ArgumentOutOfRangeException(nameof(map));
            if (id <= 0) throw new ArgumentOutOfRangeException(nameof(id));
            if (posX <= 0) throw new ArgumentOutOfRangeException(nameof(posX));
            if (posY <= 0) throw new ArgumentOutOfRangeException(nameof(posY));
            if (posZ <= 0) throw new ArgumentOutOfRangeException(nameof(posZ));
            if (ori <= 0) throw new ArgumentOutOfRangeException(nameof(ori));
            if (_clusterServiceLocator == null) return;
            if (_clusterServiceLocator.WorldCluster.ClienTs.ContainsKey(id))
            {
                var characterObject = _clusterServiceLocator.WorldCluster.ClienTs[id].Character;
                if (characterObject != null)
                    _clusterServiceLocator.WorldCluster.Log.WriteLine(LogType.INFORMATION,
                        "[{0:000000}] Client has transferred from map {1:000} to map {2:000}", id,
                        characterObject.Map, map);
            }

            using (var p = new PacketClass(SMSG_NEW_WORLD))
            {
                p.AddUInt32(map);
                p.AddSingle(posX);
                p.AddSingle(posY);
                p.AddSingle(posZ);
                p.AddSingle(ori);
                if (_clusterServiceLocator.WorldCluster.ClienTs.ContainsKey(id))
                    _clusterServiceLocator.WorldCluster.ClienTs[id].Send(p);
            }

            using (var character = _clusterServiceLocator.WorldCluster.ClienTs[id].Character)
            {
                if (character != null)
                    character.Map = map;
            }
        }

        public void ClientUpdate(uint id, uint zone, byte level)
        {
            if (_clusterServiceLocator.WorldCluster.ClienTs.ContainsKey(id))
                if (_clusterServiceLocator.WorldCluster.ClienTs != null && _clusterServiceLocator.WorldCluster != null &&
                    _clusterServiceLocator != null && _clusterServiceLocator.WorldCluster.ClienTs[id].Character is null)
                    return;
            _clusterServiceLocator.WorldCluster.Log?.WriteLine(LogType.INFORMATION,
                "[{0:000000}] Client has an updated zone {1:000}", id, zone);
            var characterObject = _clusterServiceLocator.WorldCluster.ClienTs[id].Character;
            if (characterObject == null) return;
            characterObject.Zone = zone;
            characterObject.Level = level;
        }

        public void ClientSetChatFlag(uint id, byte flag)
        {
            if (flag <= 0) throw new ArgumentOutOfRangeException(nameof(flag));
            if (id <= 0) throw new ArgumentOutOfRangeException(nameof(id));
            if (_clusterServiceLocator.WorldCluster.ClienTs.ContainsKey(id) &&
                _clusterServiceLocator.WorldCluster.ClienTs != null && _clusterServiceLocator.WorldCluster != null &&
                _clusterServiceLocator != null &&
                _clusterServiceLocator.WorldCluster.ClienTs[id].Character is null) return;
            _clusterServiceLocator.WorldCluster.Log.WriteLine(LogType.DEBUG, "[{0:000000}] Client chat flag update [0x{1:X}]", id, flag);
            var characterObject = _clusterServiceLocator.WorldCluster.ClienTs[id].Character;
            if (characterObject != null)
                characterObject.ChatFlag = (ChatFlag) flag;
        }

        public byte[] ClientGetCryptKey(uint id)
        {
            if (_clusterServiceLocator == null) return new byte[] { };
            _clusterServiceLocator.WorldCluster.Log.WriteLine(LogType.DEBUG,
                "[{0:000000}] Requested client crypt key", id);
            return _clusterServiceLocator.WorldCluster.ClienTs[id].SsHash;
        }

        public void Broadcast(byte[] data)
        {
            if (_clusterServiceLocator == null) return;
            if (_clusterServiceLocator
                .GlobalConstants != null)
                _clusterServiceLocator.WorldCluster.CharacteRsLock.AcquireReaderLock(_clusterServiceLocator
                    .GlobalConstants.DEFAULT_LOCK_TIMEOUT);
            foreach (var (_, value) in _clusterServiceLocator.WorldCluster.CharacteRs)
            {
                if (!value.IsInWorld || value.Client == null) continue;
                value.Client.Send(data);
            }
            _clusterServiceLocator.WorldCluster.CharacteRsLock.ReleaseReaderLock();
        }

        public void BroadcastGroup(long groupId, byte[] data)
        {
            var withBlock = _clusterServiceLocator.WcHandlersGroup.GrouPs[groupId];
            for (byte i = 0, loopTo = (byte) (withBlock.Members.Length - 1); i <= loopTo; i++)
            {
                if (withBlock.Members[i] != null)
                {
                    withBlock.Members[i].Client.Send((byte[]) data.Clone());
                }
            }
        }

        public void BroadcastRaid(long groupId, byte[] data)
        {
            var withBlock = _clusterServiceLocator.WcHandlersGroup.GrouPs[groupId];
            for (byte i = 0, loopTo = (byte) (withBlock.Members.Length - 1); i <= loopTo; i++)
            {
                if (withBlock.Members[i] != null && withBlock.Members[i].Client != null)
                {
                    withBlock.Members[i].Client.Send((byte[]) data.Clone());
                }
            }
        }

        public void BroadcastGuild(long guildId, byte[] data)
        {
            // TODO: Not implement yet
        }

        public void BroadcastGuildOfficers(long guildId, byte[] data)
        {
            // TODO: Not implement yet
        }

        public bool InstanceCheck(ClientClass client, uint mapId)
        {
            if (_clusterServiceLocator.WcNetwork.WorldServer != null && _clusterServiceLocator != null &&
                _clusterServiceLocator.WcNetwork.WorldServer.Worlds.ContainsKey(mapId)) return true;
            // We don't create new continents
            if (_clusterServiceLocator.Functions.IsContinentMap((int)mapId))
            {
                _clusterServiceLocator.WorldCluster.Log.WriteLine(LogType.WARNING, "[{0:000000}] Requested Instance Map [{1}] is a continent", client.Index, mapId);
                client.Send(new PacketClass(SMSG_LOGOUT_COMPLETE));
                new PacketClass(SMSG_LOGOUT_COMPLETE).Dispose();
                client.Character.IsInWorld = false;
                return false;
            }

            _clusterServiceLocator.WorldCluster.Log.WriteLine(LogType.INFORMATION, "[{0:000000}] Requesting Instance Map [{1}]", client.Index, mapId);
            IWorld parentMap = default;
            WorldInfo parentMapInfo = null;

            // Check if we got parent map
            if (_clusterServiceLocator.WcNetwork.WorldServer != null &&
                _clusterServiceLocator.WcNetwork.WorldServer.Worlds.ContainsKey(
                    (uint) _clusterServiceLocator.WsDbcDatabase.Maps[(int) mapId].ParentMap) && _clusterServiceLocator
                    .WcNetwork.WorldServer
                    .Worlds[(uint) _clusterServiceLocator.WsDbcDatabase.Maps[(int) mapId].ParentMap]
                    .InstanceCanCreate((int) _clusterServiceLocator.WsDbcDatabase.Maps[(int) mapId].Type))
            {
                parentMap = _clusterServiceLocator.WcNetwork.WorldServer.Worlds[
                    (uint) _clusterServiceLocator.WsDbcDatabase.Maps[(int) mapId].ParentMap];
                parentMapInfo =
                    _clusterServiceLocator.WcNetwork.WorldServer.WorldsInfo[
                        (uint) _clusterServiceLocator.WsDbcDatabase.Maps[(int) mapId].ParentMap];
            }
            else if (_clusterServiceLocator.WcNetwork.WorldServer != null &&
                     _clusterServiceLocator.WcNetwork.WorldServer.Worlds.ContainsKey(0U) && _clusterServiceLocator
                         .WcNetwork.WorldServer.Worlds[0U]
                         .InstanceCanCreate((int) _clusterServiceLocator.WsDbcDatabase.Maps[(int) mapId].Type))
            {
                parentMap = _clusterServiceLocator.WcNetwork.WorldServer.Worlds[0U];
                parentMapInfo = _clusterServiceLocator.WcNetwork.WorldServer.WorldsInfo[0U];
            }
            else if (_clusterServiceLocator.WcNetwork.WorldServer != null &&
                     _clusterServiceLocator.WcNetwork.WorldServer.Worlds.ContainsKey(1U) && _clusterServiceLocator
                         .WcNetwork.WorldServer.Worlds[1U]
                         .InstanceCanCreate((int) _clusterServiceLocator.WsDbcDatabase.Maps[(int) mapId].Type))
            {
                parentMap = _clusterServiceLocator.WcNetwork.WorldServer.Worlds[1U];
                parentMapInfo = _clusterServiceLocator.WcNetwork.WorldServer.WorldsInfo[1U];
            }

            if (parentMap is null)
            {
                _clusterServiceLocator.WorldCluster.Log.WriteLine(LogType.WARNING, "[{0:000000}] Requested Instance Map [{1}] can't be loaded", client.Index, mapId);
                client.Send(new PacketClass(SMSG_LOGOUT_COMPLETE));
                new PacketClass(SMSG_LOGOUT_COMPLETE).Dispose();
                client.Character.IsInWorld = false;
                return false;
            }

            if (parentMap.InstanceCreateAsync(mapId) != null) parentMap.InstanceCreateAsync(mapId).Wait();

            lock (((ICollection)Worlds).SyncRoot)
            {
                _clusterServiceLocator.WcNetwork.WorldServer.Worlds.Add(mapId, parentMap);
                _clusterServiceLocator.WcNetwork.WorldServer.WorldsInfo.Add(mapId, parentMapInfo);
            }
            return true;
        }

        public bool BattlefieldCheck(uint mapId)
        {
            // Create map
            if (_clusterServiceLocator.WcNetwork.WorldServer.Worlds.ContainsKey(mapId)) return true;
            _clusterServiceLocator.WorldCluster.Log.WriteLine(LogType.INFORMATION, "[SERVER] Requesting battlefield map [{0}]", mapId);
            IWorld parentMap = default;
            WorldInfo parentMapInfo = null;

            // Check if we got parent map
            if (_clusterServiceLocator.WcNetwork.WorldServer.Worlds.ContainsKey(
                (uint) _clusterServiceLocator.WsDbcDatabase.Maps[(int) mapId].ParentMap) && _clusterServiceLocator
                .WcNetwork.WorldServer
                .Worlds[(uint) _clusterServiceLocator.WsDbcDatabase.Maps[(int) mapId].ParentMap]
                .InstanceCanCreate((int) _clusterServiceLocator.WsDbcDatabase.Maps[(int) mapId].Type))
            {
                parentMap = _clusterServiceLocator.WcNetwork.WorldServer.Worlds[
                    (uint) _clusterServiceLocator.WsDbcDatabase.Maps[(int) mapId].ParentMap];
                parentMapInfo =
                    _clusterServiceLocator.WcNetwork.WorldServer.WorldsInfo[
                        (uint) _clusterServiceLocator.WsDbcDatabase.Maps[(int) mapId].ParentMap];
            }
            else if (_clusterServiceLocator.WcNetwork.WorldServer.Worlds.ContainsKey(0U) && _clusterServiceLocator
                .WcNetwork.WorldServer.Worlds[0U]
                .InstanceCanCreate((int) _clusterServiceLocator.WsDbcDatabase.Maps[(int) mapId].Type))
            {
                parentMap = _clusterServiceLocator.WcNetwork.WorldServer.Worlds[0U];
                parentMapInfo = _clusterServiceLocator.WcNetwork.WorldServer.WorldsInfo[0U];
            }
            else if (_clusterServiceLocator.WcNetwork.WorldServer.Worlds.ContainsKey(1U) && _clusterServiceLocator
                .WcNetwork.WorldServer.Worlds[1U]
                .InstanceCanCreate((int) _clusterServiceLocator.WsDbcDatabase.Maps[(int) mapId].Type))
            {
                parentMap = _clusterServiceLocator.WcNetwork.WorldServer.Worlds[1U];
                parentMapInfo = _clusterServiceLocator.WcNetwork.WorldServer.WorldsInfo[1U];
            }

            if (parentMap != null)
            {
                _clusterServiceLocator.WorldCluster.Log.WriteLine(LogType.WARNING, "[SERVER] Requested battlefield map [{0}] can't be loaded", mapId);
                return false;
            }

            parentMap.InstanceCreateAsync(mapId).Wait();
            lock (((ICollection)Worlds).SyncRoot)
            {
                _clusterServiceLocator.WcNetwork.WorldServer.Worlds.Add(mapId, parentMap);
                _clusterServiceLocator.WcNetwork.WorldServer.WorldsInfo.Add(mapId, parentMapInfo);
            }
            return true;
        }

        public List<int> BattlefieldList(byte mapType)
        {
            var battlefieldMap = new List<int>();
            if (_clusterServiceLocator == null) return battlefieldMap;
            _clusterServiceLocator.WcHandlersBattleground.BattlefielDsLock.AcquireReaderLock(
                _clusterServiceLocator.GlobalConstants.DEFAULT_LOCK_TIMEOUT);
            foreach (var (_, battlefield) in _clusterServiceLocator.WcHandlersBattleground.BattlefielDs)
            {
                if ((byte) battlefield.MapType == mapType)
                {
                    battlefieldMap.Add(battlefield.Id);
                }
            }
            _clusterServiceLocator.WcHandlersBattleground.BattlefielDsLock.ReleaseReaderLock();
            return battlefieldMap;
        }

        public void BattlefieldFinish(int battlefieldId)
        {
            _clusterServiceLocator?.WorldCluster.Log.WriteLine(LogType.INFORMATION,
                "[B{0:0000}] Battlefield finished", battlefieldId);
        }

        public void GroupRequestUpdate(uint id)
        {
            if (!_clusterServiceLocator.WorldCluster.ClienTs.ContainsKey(id) ||
                _clusterServiceLocator.WorldCluster.ClienTs[id].Character == null ||
                !_clusterServiceLocator.WorldCluster.ClienTs[id].Character.IsInWorld ||
                !_clusterServiceLocator.WorldCluster.ClienTs[id].Character.IsInGroup) return;
            _clusterServiceLocator.WorldCluster.Log.WriteLine(LogType.NETWORK, "[G{0:00000}] Group update request", _clusterServiceLocator.WorldCluster.ClienTs[id].Character.Group.Id);
            try
            {
                _clusterServiceLocator.WorldCluster.ClienTs[id].Character.GetWorld.GroupUpdate(
                    _clusterServiceLocator.WorldCluster.ClienTs[id].Character.Group.Id,
                    (byte) _clusterServiceLocator.WorldCluster.ClienTs[id].Character.Group.Type,
                    _clusterServiceLocator.WorldCluster.ClienTs[id].Character.Group.GetLeader().Guid,
                    _clusterServiceLocator.WorldCluster.ClienTs[id].Character.Group.GetMembers());
                _clusterServiceLocator.WorldCluster.ClienTs[id].Character.GetWorld.GroupUpdateLoot(
                    _clusterServiceLocator.WorldCluster.ClienTs[id].Character.Group.Id,
                    (byte) _clusterServiceLocator.WorldCluster.ClienTs[id].Character.Group.DungeonDifficulty,
                    (byte) _clusterServiceLocator.WorldCluster.ClienTs[id].Character.Group.LootMethod,
                    (byte) _clusterServiceLocator.WorldCluster.ClienTs[id].Character.Group.LootThreshold,
                    _clusterServiceLocator.WorldCluster.ClienTs[id].Character.Group.GetLootMaster().Guid);
            }
            catch (Exception)
            {
                _clusterServiceLocator.WcNetwork.WorldServer.Disconnect("NULL",
                    new List<uint> {_clusterServiceLocator.WorldCluster.ClienTs[id].Character.Map});
            }
        }

        public void GroupSendUpdate(long groupId)
        {
            if (_clusterServiceLocator == null) return;
            _clusterServiceLocator.WorldCluster.Log.WriteLine(LogType.NETWORK, "[G{0:00000}] Group update",
                groupId);
            var syncRoot = (Worlds as ICollection)?.SyncRoot;
            if (syncRoot == null) return;
            lock (syncRoot)
            {
                foreach (var (key, value) in Worlds)
                {
                    try
                    {
                        value.GroupUpdate(groupId,
                            (byte) _clusterServiceLocator.WcHandlersGroup.GrouPs[groupId].Type,
                            _clusterServiceLocator.WcHandlersGroup.GrouPs[groupId].GetLeader().Guid,
                            _clusterServiceLocator.WcHandlersGroup.GrouPs[groupId].GetMembers());
                    }
                    catch (Exception)
                    {
                        _clusterServiceLocator.WorldCluster.Log.WriteLine(LogType.FAILED,
                            "[G{0:00000}] Group update failed for [M{1:000}]", groupId, key);
                    }
                }
            }
        }

        public void GroupSendUpdateLoot(long groupId)
        {
            if (_clusterServiceLocator == null) return;
            _clusterServiceLocator.WorldCluster.Log.WriteLine(LogType.NETWORK, "[G{0:00000}] Group update loot",
                groupId);
            var syncRoot = (Worlds as ICollection).SyncRoot;
            lock (syncRoot)
            {
                foreach (var w in Worlds)
                {
                    try
                    {
                        w.Value.GroupUpdateLoot(groupId,
                            (byte) _clusterServiceLocator.WcHandlersGroup.GrouPs[groupId].DungeonDifficulty,
                            (byte) _clusterServiceLocator.WcHandlersGroup.GrouPs[groupId].LootMethod,
                            (byte) _clusterServiceLocator.WcHandlersGroup.GrouPs[groupId].LootThreshold,
                            _clusterServiceLocator.WcHandlersGroup.GrouPs[groupId].GetLootMaster().Guid);
                    }
                    catch (Exception)
                    {
                        _clusterServiceLocator.WorldCluster.Log.WriteLine(LogType.FAILED,
                            "[G{0:00000}] Group update loot failed for [M{1:000}]", groupId, w.Key);
                    }
                }
            }
        }
    }
}