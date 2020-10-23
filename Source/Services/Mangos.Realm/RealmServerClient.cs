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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Mangos.Common.Enums.Authentication;
using Mangos.Common.Enums.Global;
using Mangos.Common.Enums.Misc;
using Mangos.Common.Globals;
using Mangos.Loggers;
using Mangos.Network.Tcp;
using Mangos.Network.Tcp.Extensions;
using Mangos.Storage.Account;
using Microsoft.VisualBasic;
using Microsoft.VisualBasic.CompilerServices;
using static System.Array;
using static System.BitConverter;
using static System.Enum;
using static System.IO.FileMode;
using static System.String;
using static Mangos.Common.Enums.Authentication.AuthCMD;
using static Mangos.Common.Enums.Global.AccountState;
using static Mangos.Realm.AuthEngineClass;
using static Microsoft.VisualBasic.CompilerServices.Conversions;
using static Microsoft.VisualBasic.CompilerServices.Operators;
using static Microsoft.VisualBasic.Conversion;
using static Microsoft.VisualBasic.FileSystem;

namespace Mangos.Realm
{
    public class RealmServerClient : ITcpClient
    {
        private readonly ILogger _logger;
        private readonly IAccountStorage _accountStorage;
        private readonly Converter _converter;
        private readonly MangosGlobalConstants _mangosGlobalConstants;

        private readonly AuthEngineClass _authEngineClass = new AuthEngineClass();

        private readonly Dictionary<AuthCMD, Func<ChannelReader<byte>, ChannelWriter<byte>, Task>> _packetHandlers;
        private readonly IPEndPoint _remoteEnpoint;


        public string Account = "";
        public string UpdateFile = "";
        public AccessLevel Access = AccessLevel.Player;

        public RealmServerClient(ILogger logger,
            IAccountStorage accountStorage,
            Converter converter,
            MangosGlobalConstants mangosGlobalConstants,
            IPEndPoint remoteEnpoint)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            if (accountStorage != null) _accountStorage = accountStorage;
            if (converter != null) _converter = converter;
            if (mangosGlobalConstants != null) _mangosGlobalConstants = mangosGlobalConstants;
            if (remoteEnpoint != null) _remoteEnpoint = remoteEnpoint;

            _packetHandlers = GetPacketHandlers();
        }

        public async void HandleAsync(
            ChannelReader<byte> reader,
            ChannelWriter<byte> writer,
            CancellationToken cancellationToken)
        {
            if (reader == null) throw new ArgumentNullException(nameof(reader));
            if (writer == null) throw new ArgumentNullException(nameof(writer));
            while (!cancellationToken.IsCancellationRequested)
            {
                var header = await reader.ReadAsync(1).ToListAsync(cancellationToken);
                if (header.Count <= 0) continue;
                var opcode = (AuthCMD)header[0];

                if (_packetHandlers.ContainsKey(opcode)) await _packetHandlers[opcode](reader, writer);
            }
        }

        private Dictionary<AuthCMD, Func<ChannelReader<byte>, ChannelWriter<byte>, Task>> GetPacketHandlers()
        {
            return new Dictionary<AuthCMD, Func<ChannelReader<byte>, ChannelWriter<byte>, Task>>
            {
                [CMD_AUTH_LOGON_CHALLENGE] = On_RS_LOGON_CHALLENGE,
                [CMD_AUTH_RECONNECT_CHALLENGE] = On_RS_LOGON_CHALLENGE,
                [CMD_AUTH_LOGON_PROOF] = On_RS_LOGON_PROOF,
                [CMD_AUTH_REALMLIST] = On_RS_REALMLIST,
                [CMD_XFER_ACCEPT] = On_CMD_XFER_ACCEPT,
                [CMD_XFER_RESUME] = On_CMD_XFER_RESUME,
                [CMD_XFER_CANCEL] = On_CMD_XFER_CANCEL,
            };
        }

        public async Task On_RS_LOGON_CHALLENGE(ChannelReader<byte> reader, ChannelWriter<byte> writer)
        {
            if (reader != null)
            {
                var header = await reader.ReadAsync(3).ToListAsync();
                var length = ToInt16(new[] { header[1], header[2] });
                var body = await reader.ReadAsync(length).ToListAsync();
                var data = new byte[1].Concat(header).Concat(body).ToArray();

                if (data.Length > 33)
                {
                    var iUpper = data[33] - 1;
                    // Read account name from packet
                    var packetAccount = "";
                    for (int i = 0, loopTo = iUpper; i <= loopTo; i++)
                        packetAccount += Conversions.ToString((char)data[34 + i]);
                    Account = packetAccount;

                    // Read users ip from packet
                    if (data.Length > 29)
                    {
                        if (data.Length > 30)
                        {
                            if (data.Length > 31)
                            {
                                if (data.Length > 32)
                                {
                                    var packetIp = (int)data[29] + "." + ((int)data[30]) + "." + (int)data[31] + "." + ((int)data[32]);
                                }
                            }
                        }
                    }

                    // Get the client build from packet.
                    if (data.Length > 8)
                    {
                        int bMajor = data[8];
                        if (data.Length > 9)
                        {
                            int bMinor = data[9];
                            if (data.Length > 10)
                            {
                                int bRevision = data[10];
                                if (data.Length > 11)
                                {
                                    if (data.Length > 12)
                                    {
                                        int clientBuild = ToInt16(new[] { data[11], data[12] }, 0);
                                        if (data.Length > 24)
                                        {
                                            if (data.Length > 23)
                                            {
                                                if (data.Length > 22)
                                                {
                                                    if (data.Length > 21)
                                                    {
                                                        var clientLanguage = Conversions.ToString((char)data[24]) + (char)data[23] + (char)data[22] + (char)data[21];
                                                    }
                                                }
                                            }
                                        }

                                        // DONE: Check if our build can join the server
                                        // If ((RequiredVersion1 = 0 AndAlso RequiredVersion2 = 0 AndAlso RequiredVersion3 = 0) OrElse
                                        // (bMajor = RequiredVersion1 AndAlso bMinor = RequiredVersion2 AndAlso bRevision = RequiredVersion3)) AndAlso
                                        // clientBuild >= RequiredBuildLow AndAlso clientBuild <= RequiredBuildHigh Then
                                        if (bMajor == 0 & bMinor == 0 & bRevision == 0)
                                        {
                                            var dataResponse = new byte[2];
                                            if (dataResponse.Length > 0) dataResponse[0] = (byte)CMD_AUTH_LOGON_PROOF;
                                            if (dataResponse.Length > 1)
                                                dataResponse[1] = (byte)LOGIN_BADVERSION;
                                            await writer.WriteAsync(dataResponse);
                                        }
                                        else if (_mangosGlobalConstants != null && clientBuild == _mangosGlobalConstants.Required_Build_1_12_1 |
                                            clientBuild == _mangosGlobalConstants.Required_Build_1_12_2 |
                                            clientBuild == _mangosGlobalConstants.Required_Build_1_12_3)
                                        {
                                            // TODO: in the far future should check if the account is expired too
                                            if (_accountStorage != null)
                                            {
                                                var accountInfo = await _accountStorage.GetAccountInfoAsync(packetAccount);
                                                AccountState accState;
                                                try
                                                {
                                                    // Check Account state
                                                    if (accountInfo != null)
                                                    {
                                                        accState = await _accountStorage.IsBannedAccountAsync(accountInfo.id)
                                                            ? LOGIN_BANNED
                                                            : LOGIN_OK;
                                                    }
                                                    else
                                                    {
                                                        accState = LOGIN_UNKNOWN_ACCOUNT;
                                                    }
                                                }
                                                catch
                                                {
                                                    accState = LOGIN_DBBUSY;
                                                }

                                                // DONE: Send results to client
                                                switch (accState)
                                                {
                                                    case var @case when @case == LOGIN_OK:
                                                    {
                                                        if (data.Length > 33)
                                                        {
                                                            var account = new byte[(data[33])];
                                                            if (data.Length > 33) Copy(data, 34, account, 0, data[33]);
                                                            if (accountInfo?.sha_pass_hash != null && ToBoolean(ConditionalCompareObjectNotEqual(
                                                                accountInfo.sha_pass_hash.Length, 40, false))
                                                            ) // Invalid password type, should always be 40 characters
                                                            {
                                                                var dataResponse = new byte[2];
                                                                if (dataResponse.Length > 0)
                                                                    dataResponse[0] = (byte)CMD_AUTH_LOGON_PROOF;
                                                                if (dataResponse.Length > 1) dataResponse[1] = (byte)LOGIN_BAD_PASS;
                                                                await writer.WriteAsync(dataResponse);
                                                            }
                                                            else // Bail out with something meaningful
                                                            {
                                                                if (accountInfo == null) return;
                                                                if (accountInfo.gmlevel != null)
                                                                    Access = (AccessLevel) Parse(typeof(AccessLevel),
                                                                        accountInfo.gmlevel);
                                                                var hash = new byte[20];
                                                                for (var i = 0; i <= 39; i += 2)
                                                                    if (accountInfo.sha_pass_hash != null)
                                                                        hash[i / 2] =
                                                                            (byte) ToInteger(ConcatenateObject("&H",
                                                                                accountInfo.sha_pass_hash.Substring(i,
                                                                                    2)));

                                                                // Language = clientLanguage
                                                                // If Not IsDBNull(result.Rows(0).Item("expansion")) Then
                                                                // Expansion = result.Rows(0).Item("expansion")
                                                                // Else
                                                                // Expansion = ExpansionLevel.NORMAL
                                                                // End If

                                                                try
                                                                {
                                                                    _authEngineClass.CalculateX(account, hash);
                                                                    var dataResponse = new byte[119];
                                                                    if (dataResponse.Length > 0)
                                                                        dataResponse[0] =
                                                                            (byte) CMD_AUTH_LOGON_CHALLENGE;
                                                                    if (dataResponse.Length > 1)
                                                                        dataResponse[1] = (byte) LOGIN_OK;
                                                                    if (dataResponse.Length > 2)
                                                                        dataResponse[2] = (byte) Val("&H00");
                                                                    Copy(_authEngineClass.PublicB, 0, dataResponse,
                                                                        3, 32);
                                                                    if (dataResponse.Length > 35)
                                                                        dataResponse[35] =
                                                                            (byte) _authEngineClass.g.Length;
                                                                    if (dataResponse.Length > 36)
                                                                        dataResponse[36] = _authEngineClass.g[0];
                                                                    if (dataResponse.Length > 37) dataResponse[37] = 32;
                                                                    Copy(_authEngineClass.N, 0, dataResponse, 38,
                                                                        32);
                                                                    Copy(_authEngineClass.Salt, 0, dataResponse, 70,
                                                                        32);
                                                                    Copy(CrcSalt, 0, dataResponse,
                                                                        102, 16);
                                                                    if (dataResponse.Length > 118)
                                                                        dataResponse[118] =
                                                                            0; // Added in 1.12.x client branch? Security Flags (&H0...&H4)?
                                                                    await writer.WriteAsync(dataResponse);
                                                                }
                                                                catch (Exception ex)
                                                                {
                                                                    _logger.Error("Error loading AuthEngine: {0}",
                                                                        ex);
                                                                }
                                                            }
                                                        }

                                                        return;
                                                    }

                                                    case var case1 when case1 == LOGIN_UNKNOWN_ACCOUNT:
                                                    {
                                                        var dataResponse = new byte[2];
                                                        if (dataResponse.Length > 0)
                                                            dataResponse[0] = (byte)CMD_AUTH_LOGON_PROOF;
                                                        if (dataResponse.Length > 1)
                                                            dataResponse[1] = (byte)LOGIN_UNKNOWN_ACCOUNT;
                                                        await writer.WriteAsync(dataResponse);
                                                        return;
                                                    }

                                                    case var case2 when case2 == LOGIN_BANNED:
                                                    {
                                                        var dataResponse = new byte[2];
                                                        if (dataResponse.Length > 0)
                                                            dataResponse[0] = (byte)CMD_AUTH_LOGON_PROOF;
                                                        if (dataResponse.Length > 1)
                                                            dataResponse[1] = (byte)LOGIN_BANNED;
                                                        await writer.WriteAsync(dataResponse);
                                                        return;
                                                    }

                                                    case var case3 when case3 == LOGIN_NOTIME:
                                                    {
                                                        var dataResponse = new byte[2];
                                                        if (dataResponse.Length > 0)
                                                            dataResponse[0] = (byte)CMD_AUTH_LOGON_PROOF;
                                                        if (dataResponse.Length > 1)
                                                            dataResponse[1] = (byte)LOGIN_NOTIME;
                                                        await writer.WriteAsync(dataResponse);
                                                        return;
                                                    }

                                                    case var case4 when case4 == LOGIN_ALREADYONLINE:
                                                    {
                                                        var dataResponse = new byte[2];
                                                        if (dataResponse.Length > 0)
                                                            dataResponse[0] = (byte)CMD_AUTH_LOGON_PROOF;
                                                        if (dataResponse.Length > 1)
                                                            dataResponse[1] = (byte)LOGIN_ALREADYONLINE;
                                                        await writer.WriteAsync(dataResponse);
                                                        return;
                                                    }

                                                    case var case5 when case5 == LOGIN_FAILED:
                                                    {
                                                        break;
                                                    }

                                                    case var case6 when case6 == LOGIN_BAD_PASS:
                                                    {
                                                        break;
                                                    }

                                                    case var case7 when case7 == LOGIN_DBBUSY:
                                                    {
                                                        break;
                                                    }

                                                    case var case8 when case8 == LOGIN_BADVERSION:
                                                    {
                                                        break;
                                                    }

                                                    case var case9 when case9 == LOGIN_DOWNLOADFILE:
                                                    {
                                                        break;
                                                    }

                                                    case var case10 when case10 == LOGIN_SUSPENDED:
                                                    {
                                                        break;
                                                    }

                                                    case var case11 when case11 == LOGIN_PARENTALCONTROL:
                                                    {
                                                        break;
                                                    }

                                                    default:
                                                    {
                                                        var dataResponse = new byte[2];
                                                        if (dataResponse.Length > 0)
                                                            dataResponse[0] = (byte)CMD_AUTH_LOGON_PROOF;
                                                        if (dataResponse.Length > 1)
                                                            dataResponse[1] = (byte)LOGIN_FAILED;
                                                        await writer.WriteAsync(dataResponse);
                                                        return;
                                                    }
                                                }
                                            }
                                        }
                                        else if (!IsNullOrEmpty(Dir("Updates/wow-patch-" +
                                                                    Val("&H" + Hex(data[12]) + Hex(data[11])) + "-" +
                                                                    (char) data[24] + (char) data[23] +
                                                                    (char) data[22] + (char) data[21] + ".mpq")))
                                        {
                                            // Send UPDATE_MPQ
                                            UpdateFile = "Updates/wow-patch-" +
                                                         Val("&H" + Hex(data[12]) + Hex(data[11])) + "-" +
                                                         (char) data[24] + (char) data[23] + (char) data[22] +
                                                         (char) data[21] + ".mpq";
                                            var dataResponse = new byte[31];
                                            if (dataResponse.Length > 0) dataResponse[0] = (byte)CMD_XFER_INITIATE;
                                            // Name Len 0x05 -> sizeof(Patch)
                                            var i = 1;
                                            _converter.ToBytes(ToByte(5), dataResponse, ref i);
                                            // Name 'Patch'
                                            _converter.ToBytes("Patch", dataResponse, ref i);
                                            // Size 0x34 C4 0D 00 = 902,196 byte (180->181 enGB)
                                            _converter.ToBytes(ToInteger(FileLen(UpdateFile)), dataResponse, ref i);
                                            // Unknown 0x0 always
                                            _converter.ToBytes(0, dataResponse, ref i);
                                            // MD5 CheckSum
                                            byte[] result;
                                            using (var md5 = new MD5CryptoServiceProvider())
                                            {
                                                BinaryReader r;
                                                await using (var fs = new FileStream(UpdateFile, Open))
                                                {
                                                    r = new BinaryReader(fs);
                                                }

                                                var buffer = r.ReadBytes((int)FileLen(UpdateFile));
                                                r.Close();
                                                // fs.Close()
                                                result = md5.ComputeHash(buffer);
                                            }

                                            Copy(result, 0, dataResponse, 15, 16);
                                            await writer.WriteAsync(dataResponse);
                                        }
                                        else
                                        {
                                            // Send BAD_VERSION
                                            _logger.Warning("WRONG_VERSION [" + (char) data[6] + (char) data[5] +
                                                            (char) data[4] + " " + data[8] + "." + data[9] + "." +
                                                            data[10] + "." + Val("&H" + Hex(data[12]) + Hex(data[11])) +
                                                            " " + (char) data[15] + (char) data[14] + (char) data[13] +
                                                            " " + (char) data[19] + (char) data[18] + (char) data[17] +
                                                            " " + (char) data[24] + (char) data[23] + (char) data[22] +
                                                            (char) data[21] + "]");
                                            var dataResponse = new byte[2];
                                            dataResponse[0] = (byte)CMD_AUTH_LOGON_PROOF;
                                            dataResponse[1] = (byte)LOGIN_BADVERSION;
                                            await writer.WriteAsync(dataResponse);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        public async Task On_RS_LOGON_PROOF(ChannelReader<byte> reader, ChannelWriter<byte> writer)
        {
            var body = await reader.ReadAsync(74).ToListAsync();
            var data = new byte[1].Concat(body).ToArray();

            var a = new byte[32];
            Copy(data, 1, a, 0, 32);
            var m1 = new byte[20];
            Copy(data, 33, m1, 0, 20);
            // Dim CRC_Hash(19) As Byte
            // Array.Copy(data, 53, CRC_Hash, 0, 20)
            // Dim NumberOfKeys as Byte = data(73)
            // Dim unk as Byte = data(74)

            // Calculate U and M1
            _authEngineClass.CalculateU(a);
            _authEngineClass.CalculateM1();
            // AuthEngine.CalculateCRCHash()

            // Check M1=ClientM1
            var passCheck = true;
            for (byte i = 0; i <= 19; i++)
            {
                if (m1[i] != _authEngineClass.M1[i])
                {
                    passCheck = false;
                    break;
                }
            }

            if (!passCheck)
            {
                // Wrong pass
                _logger.Debug("Wrong password for user {0}.", Account);
                var dataResponse = new byte[2];
                dataResponse[0] = (byte)CMD_AUTH_LOGON_PROOF;
                dataResponse[1] = (byte)LOGIN_BAD_PASS;
                await writer.WriteAsync(dataResponse);
            }
            else
            {
                _authEngineClass.CalculateM2(m1);
                var dataResponse = new byte[26];
                dataResponse[0] = (byte)CMD_AUTH_LOGON_PROOF;
                dataResponse[1] = (byte)LOGIN_OK;
                Copy(_authEngineClass.M2, 0, dataResponse, 2, 20);
                dataResponse[22] = 0;
                dataResponse[23] = 0;
                dataResponse[24] = 0;
                dataResponse[25] = 0;
                await writer.WriteAsync(dataResponse);

                // Set SSHash in DB
                var sshash = "";

                // For i as Integer = 0 To AuthEngine.SS_Hash.Length - 1
                for (var i = 0; i <= 40 - 1; i++)
                    sshash = _authEngineClass.SsHash[i] < 16 ? sshash + "0" + Hex(_authEngineClass.SsHash[i]) : sshash + Hex(_authEngineClass.SsHash[i]);
                await _accountStorage.UpdateAccountAsync(sshash, _remoteEnpoint.Address.ToString(), Strings.Format(DateAndTime.Now, "yyyy-MM-dd"), Account);
                _logger.Debug("Auth success for user {0} [{1}]", Account, sshash);
            }
        }

        public async Task On_RS_REALMLIST(ChannelReader<byte> reader, ChannelWriter<byte> writer)
        {
            var body = await reader.ReadAsync(4).ToListAsync();
            var data = new byte[1].Concat(body).ToArray();

            var packetLen = 0;

            // Fetch RealmList Data
            var realmList = await _accountStorage.GetRealmListAsync();
            foreach (var row in realmList)
            {
                packetLen = packetLen
                    + Strings.Len(row.address)
                    + Strings.Len(row.name)
                    + 1
                    + Strings.Len(row.port)
                    + 14;
            }

            var dataResponse = new byte[packetLen + 9 + 1];

            // (byte) Opcode
            dataResponse[0] = (byte)CMD_AUTH_REALMLIST;

            // (uint16) Packet Length
            dataResponse[2] = (byte)((packetLen + 7) / 256);
            dataResponse[1] = (byte)((packetLen + 7) % 256);

            // (uint32) Unk
            dataResponse[3] = data[1];
            dataResponse[4] = data[2];
            dataResponse[5] = data[3];
            dataResponse[6] = data[4];

            // (uint16) Realms Count
            dataResponse[7] = (byte)realmList.Count();
            dataResponse[8] = 0;
            var tmp = 8;
            foreach (var realmListItem in realmList)
            {
                // Get Number of Characters for the Realm
                var characterCount = await _accountStorage.GetNumcharsAsync(realmListItem.id);

                // (uint8) Realm Icon
                // 0 -> Normal; 1 -> PvP; 6 -> RP; 8 -> RPPvP;
                _converter.ToBytes(ToByte(realmListItem.icon), dataResponse, ref tmp);
                // (uint8) IsLocked
                // 0 -> none; 1 -> locked
                _converter.ToBytes(ToByte(0), dataResponse, ref tmp);
                // (uint8) unk
                _converter.ToBytes(ToByte(0), dataResponse, ref tmp);
                // (uint8) unk
                _converter.ToBytes(ToByte(0), dataResponse, ref tmp);
                // (uint8) Realm Color
                // 0 -> Green; 1 -> Red; 2 -> Offline;
                _converter.ToBytes(ToByte(realmListItem.realmflags), dataResponse, ref tmp);
                // (string) Realm Name (zero terminated)
                _converter.ToBytes(Conversions.ToString(realmListItem.name), dataResponse, ref tmp);
                _converter.ToBytes(ToByte(0), dataResponse, ref tmp); // \0
                                                                                 // (string) Realm Address ("ip:port", zero terminated)
                _converter.ToBytes(ConcatenateObject(ConcatenateObject(realmListItem.address, ":"), realmListItem.port).ToString(), dataResponse, ref tmp);
                _converter.ToBytes(ToByte(0), dataResponse, ref tmp); // \0
                                                                                 // (float) Population
                                                                                 // 400F -> Full; 5F -> Medium; 1.6F -> Low; 200F -> New; 2F -> High
                                                                                 // 00 00 48 43 -> Recommended
                                                                                 // 00 00 C8 43 -> Full
                                                                                 // 9C C4 C0 3F -> Low
                                                                                 // BC 74 B3 3F -> Low
                _converter.ToBytes(ToSingle(realmListItem.population), dataResponse, ref tmp);
                // (byte) Number of character at this realm for this account
                _converter.ToBytes(ToByte(characterCount), dataResponse, ref tmp);
                // (byte) Timezone
                // 0x01 - Development
                // 0x02 - USA
                // 0x03 - Oceania
                // 0x04 - LatinAmerica
                // 0x05 - Tournament
                // 0x06 - Korea
                // 0x07 - Tournament
                // 0x08 - UnitedKingdom
                // 0x09 - Germany
                // 0x0A - France
                // 0x0B - Spain
                // 0x0C - Russian
                // 0x0D - Tournament
                // 0x0E - Taiwan
                // 0x0F - Tournament
                // 0x10 - China
                // 0x11 - CN1
                // 0x12 - CN2
                // 0x13 - CN3
                // 0x14 - CN4
                // 0x15 - CN5
                // 0x16 - CN6
                // 0x17 - CN7
                // 0x18 - CN8
                // 0x19 - Tournament
                // 0x1A - Test Server
                // 0x1B - Tournament
                // 0x1C - QA Server
                // 0x1D - CN9
                // 0x1E - Test Server 2
                _converter.ToBytes(ToByte(realmListItem.timezone), dataResponse, ref tmp);
                // (byte) Unknown (may be 2 -> TestRealm, / 6 -> ?)
                _converter.ToBytes(ToByte(0), dataResponse, ref tmp);
            }

            dataResponse[tmp] = 2; // 2=list of realms 0=wizard
            dataResponse[tmp + 1] = 0;
            await writer.WriteAsync(dataResponse);
        }

        public async Task On_CMD_XFER_CANCEL(ChannelReader<byte> reader, ChannelWriter<byte> writer)
        {
            // TODO: data parameter is never used
            // logger.Debug("[{0}:{1}] CMD_XFER_CANCEL", Ip, Port);
            // Socket.Close();
        }

        public async Task On_CMD_XFER_ACCEPT(ChannelReader<byte> reader, ChannelWriter<byte> writer)
        {
            // TODO: data parameter is never used			
        }

        public async Task On_CMD_XFER_RESUME(ChannelReader<byte> reader, ChannelWriter<byte> writer)
        {
            await reader.ReadAsync(8).ToListAsync();
        }
    }
}
