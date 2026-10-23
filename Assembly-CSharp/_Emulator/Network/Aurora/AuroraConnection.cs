using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using UnityEngine;
using Debug = UnityEngine.Debug;

namespace _Emulator
{
    /// <summary>
    /// Client side of the Aurora standalone server protocol (Java GameServer, "Aurora Server").
    ///
    /// Active when the launcher wrote an account play ticket into launcher_data.dat. Then the game connects to the configured server
    /// instead of starting the in-process emulator and logs in with the ticket instead of username/password:
    ///
    /// C -> S 1004 HandshakeInitialize  bytes modulus, bytes exponent (client RSA-1024 key, big endian)
    /// S -> C 1005 HandshakeChallenge   bytes modulus, bytes exponent, bytes challenge (encrypted with client key)
    /// C -> S 1006 HandshakeComplete    bytes challenge (re-encrypted with server key)
    /// S -> C 1007 RequestLogin         [client key] int login type mask
    /// C -> S 1008 Login                [server key] int major, minor, patch, revision, int login type, string name, string ticket
    /// S -> C 1010 LoggedIn, followed by the original login packets (channels, player info, item list, ...)
    /// S -> C 1002 Notification string / 1003 Disconnect string / 1001 Heartbeat
    /// C -> S 1000 Heartbeat            bool requestsHeartbeat
    ///
    /// RSA is PKCS#1 v1.5, the plain text is split into chunks of (keyBytes - 11) and every chunk becomes one keyBytes block.
    /// The opcodes 1000-1010 overlap with the emulator extension opcodes, so they are only interpreted here while Aurora mode is active.
    /// </summary>
    public class AuroraConnection : MonoBehaviour
    {
        public static AuroraConnection instance;

        private const ushort SB_HEARTBEAT = 1000;
        private const ushort CB_HEARTBEAT = 1001;
        private const ushort CB_NOTIFICATION = 1002;
        private const ushort CB_DISCONNECT = 1003;
        private const ushort SB_HANDSHAKE_INITIALIZE = 1004;
        private const ushort CB_HANDSHAKE_CHALLENGE = 1005;
        private const ushort SB_HANDSHAKE_COMPLETE = 1006;
        private const ushort CB_REQUEST_LOGIN = 1007;
        private const ushort SB_LOGIN = 1008;
        private const ushort CB_LOGIN_DETAILS = 1009;
        private const ushort CB_LOGGED_IN = 1010;

        private const int LOGIN_TYPE_ACCOUNT_TICKET = 0x8;
        private const float HEARTBEAT_INTERVAL = 1f;

        private enum State
        {
            Inactive,
            WaitingForLoginScene,
            Connecting,
            WaitingForChallenge,
            WaitingForLoginRequest,
            WaitingForLoggedIn,
            LoggedIn,
            Failed
        }

        private State state = State.Inactive;
        private string ticket = string.Empty;
        private string serverHost = string.Empty;
        private int serverPort = 18890;

        private RSACryptoServiceProvider clientKey;
        private RSACryptoServiceProvider serverKey;
        private float heartbeatTimer;

        /// <summary>
        /// True while the game talks to an Aurora standalone server, the emulator extension protocol must not be used then.
        /// </summary>
        public static bool Active
        {
            get { return instance != null && instance.state != State.Inactive; }
        }

        private void Awake()
        {
            LoadLauncherData();
        }

        private void LoadLauncherData()
        {
            try
            {
                string path = Path.GetFullPath(Path.Combine(Application.dataPath, "../launcher_data.dat"));
                if (!File.Exists(path))
                {
                    return;
                }
                using (var fs = File.OpenRead(path))
                using (var br = new BinaryReader(fs))
                {
                    CompoundTag root = br.ReadAsNbt().Value;
                    if (root == null || !root.Has("aurora.ticket", TagType.STRING))
                    {
                        return;
                    }
                    ticket = root.GetString("aurora.ticket");
                    serverHost = root.Has("aurora.server.host", TagType.STRING) ? root.GetString("aurora.server.host") : string.Empty;
                    if (root.Has("aurora.server.port", TagType.INT))
                    {
                        serverPort = root.GetInt("aurora.server.port");
                    }
                }
                if (!string.IsNullOrEmpty(ticket) && !string.IsNullOrEmpty(serverHost))
                {
                    state = State.WaitingForLoginScene;
                    Debug.Log("[Aurora] Account login enabled, server " + serverHost + ":" + serverPort);
                }
            }
            catch (Exception ex)
            {
                Debug.LogWarning("[Aurora] Failed to read launcher_data.dat: " + ex.Message);
            }
        }

        private void Update()
        {
            switch (state)
            {
                case State.WaitingForLoginScene:
                    TryConnect();
                    break;
                case State.Connecting:
                    SendHandshakeInitialize();
                    break;
                case State.LoggedIn:
                    heartbeatTimer += Time.deltaTime;
                    if (heartbeatTimer >= HEARTBEAT_INTERVAL)
                    {
                        heartbeatTimer = 0f;
                        MsgBody body = new MsgBody();
                        body.Write(false);
                        Send(SB_HEARTBEAT, body);
                    }
                    break;
            }
        }

        /// <summary>
        /// Opens the connection as soon as the login screen exists (same way the emulator joins a host).
        /// </summary>
        private void TryConnect()
        {
            GameObject main = GameObject.Find("Main");
            Login login = main != null ? main.GetComponentInChildren<Login>() : null;
            if (login == null)
            {
                return;
            }
            MainGUI.instance.setupHidden = true;
            CSNetManager.Instance.BfServer = serverHost;
            CSNetManager.Instance.BfPort = serverPort;
            state = State.Connecting;
            login.BroadcastMessage("OnRoundRobin");
            if (login.loginStep == Login.LOGIN_STEP.NONE)
            {
                Fail("Couldn't connect to the server " + serverHost + ":" + serverPort);
            }
        }

        private void SendHandshakeInitialize()
        {
            SockTcp sock = CSNetManager.Instance.Sock;
            if (sock == null || !sock.IsConnected())
            {
                return;
            }
            clientKey = new RSACryptoServiceProvider(1024);
            RSAParameters parameters = clientKey.ExportParameters(false);
            MsgBody body = new MsgBody();
            body.Write(parameters.Modulus);
            body.Write(parameters.Exponent);
            state = State.WaitingForChallenge;
            Send(SB_HANDSHAKE_INITIALIZE, body);
        }

        /// <summary>
        /// Called for every received message before the emulator/original handlers.
        /// </summary>
        /// <returns>true if the message was consumed</returns>
        public bool HandleMessage(Msg2Handle msg)
        {
            if (!Active || msg._id < SB_HEARTBEAT || msg._id > CB_LOGGED_IN)
            {
                return false;
            }
            try
            {
                switch (msg._id)
                {
                    case CB_HEARTBEAT:
                        break;
                    case CB_NOTIFICATION:
                        {
                            msg._msg.Read(out string message);
                            MessageBoxMgr.Instance.AddMessage(message);
                            break;
                        }
                    case CB_DISCONNECT:
                        {
                            msg._msg.Read(out string message);
                            Fail(message);
                            break;
                        }
                    case CB_HANDSHAKE_CHALLENGE:
                        HandleChallenge(msg._msg);
                        break;
                    case CB_REQUEST_LOGIN:
                        HandleRequestLogin(msg._msg);
                        break;
                    case CB_LOGIN_DETAILS:
                        Fail("The server requested a login type this client doesn't support.");
                        break;
                    case CB_LOGGED_IN:
                        HandleLoggedIn();
                        break;
                }
            }
            catch (Exception ex)
            {
                Debug.LogError("[Aurora] Failed to handle message " + msg._id + ": " + ex);
                Fail("Connection to the server failed (" + ex.Message + ")");
            }
            return true;
        }

        private void HandleChallenge(MsgBody body)
        {
            if (state != State.WaitingForChallenge)
            {
                return;
            }
            body.Read(out byte[] modulus);
            body.Read(out byte[] exponent);
            body.Read(out byte[] encryptedChallenge);

            serverKey = new RSACryptoServiceProvider();
            RSAParameters parameters = new RSAParameters();
            parameters.Modulus = modulus;
            parameters.Exponent = exponent;
            serverKey.ImportParameters(parameters);

            byte[] challenge = Decrypt(encryptedChallenge, clientKey);
            MsgBody response = new MsgBody();
            response.Write(Encrypt(challenge, serverKey));
            state = State.WaitingForLoginRequest;
            Send(SB_HANDSHAKE_COMPLETE, response);
        }

        private void HandleRequestLogin(MsgBody body)
        {
            if (state != State.WaitingForLoginRequest)
            {
                return;
            }
            MsgBody plain = PlainBody(Decrypt(body.Buffer, clientKey));
            plain.Read(out int supportedTypes);
            if ((supportedTypes & LOGIN_TYPE_ACCOUNT_TICKET) == 0)
            {
                Fail("This server doesn't support Aurora account logins.");
                return;
            }
            Version version = Core.Version;
            MsgBody login = new MsgBody();
            login.Write(version.Major);
            login.Write(version.Minor);
            login.Write(version.Patch);
            login.Write(version.Revision);
            login.Write(LOGIN_TYPE_ACCOUNT_TICKET);
            login.Write(string.Empty); // the server takes the name from the account
            login.Write(ticket);
            state = State.WaitingForLoggedIn;
            SendRaw(SB_LOGIN, Encrypt(Trim(login), serverKey));
        }

        private void HandleLoggedIn()
        {
            if (state != State.WaitingForLoggedIn)
            {
                return;
            }
            state = State.LoggedIn;
            heartbeatTimer = 0f;
            CSNetManager.Instance.Sock._heartbeat = true;
            Core.SetBalancedItemProperties();
            GameObject main = GameObject.Find("Main");
            Login login = main != null ? main.GetComponentInChildren<Login>() : null;
            if (login != null)
            {
                // The server sends the original login packets on its own, no CS_LOGIN_REQ is needed
                login.loginStep = Login.LOGIN_STEP.WAITING_LOGIN;
            }
            Debug.Log("[Aurora] Logged in");
        }

        private void Fail(string message)
        {
            Debug.LogWarning("[Aurora] " + message);
            state = State.Failed;
            if (CSNetManager.Instance.Sock != null)
            {
                CSNetManager.Instance.Sock.Close();
            }
            MessageBoxMgr.Instance.AddMessage(message);
            GameObject main = GameObject.Find("Main");
            Login login = main != null ? main.GetComponentInChildren<Login>() : null;
            if (login != null)
            {
                login.loginStep = Login.LOGIN_STEP.NONE;
            }
        }

        /*
         * Sending
         */

        private void Send(ushort id, MsgBody body)
        {
            SockTcp sock = CSNetManager.Instance.Sock;
            if (sock != null)
            {
                sock.Say(id, body, false);
            }
        }

        private void SendRaw(ushort id, byte[] bytes)
        {
            MsgBody body = new MsgBody();
            for (int i = 0; i < bytes.Length; i++)
            {
                body.Write(bytes[i]);
            }
            Send(id, body);
        }

        /*
         * Crypto helpers
         */

        private static byte[] Trim(MsgBody body)
        {
            byte[] bytes = new byte[body.Offset];
            Array.Copy(body.Buffer, 0, bytes, 0, body.Offset);
            return bytes;
        }

        private static MsgBody PlainBody(byte[] bytes)
        {
            return new MsgBody(bytes, 0, bytes.Length);
        }

        private static int BlockSize(RSACryptoServiceProvider key)
        {
            return key.KeySize / 8;
        }

        private static byte[] Encrypt(byte[] plain, RSACryptoServiceProvider key)
        {
            int blockSize = BlockSize(key);
            int chunkSize = blockSize - 11;
            int chunks = Math.Max(1, (plain.Length + chunkSize - 1) / chunkSize);
            byte[] output = new byte[chunks * blockSize];
            for (int i = 0; i < chunks; i++)
            {
                int offset = i * chunkSize;
                int length = Math.Min(chunkSize, plain.Length - offset);
                byte[] chunk = new byte[length];
                Array.Copy(plain, offset, chunk, 0, length);
                byte[] block = key.Encrypt(chunk, false);
                Array.Copy(block, 0, output, i * blockSize, blockSize);
            }
            return output;
        }

        private static byte[] Decrypt(byte[] encrypted, RSACryptoServiceProvider key)
        {
            int blockSize = BlockSize(key);
            if (encrypted.Length == 0 || encrypted.Length % blockSize != 0)
            {
                throw new CryptographicException("Encrypted data is not a multiple of " + blockSize + " bytes");
            }
            using (MemoryStream output = new MemoryStream(encrypted.Length))
            {
                for (int offset = 0; offset < encrypted.Length; offset += blockSize)
                {
                    byte[] block = new byte[blockSize];
                    Array.Copy(encrypted, offset, block, 0, blockSize);
                    byte[] plain = key.Decrypt(block, false);
                    output.Write(plain, 0, plain.Length);
                }
                return output.ToArray();
            }
        }
    }
}
