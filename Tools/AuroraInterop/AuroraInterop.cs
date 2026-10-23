// Interop check of the C# client crypto/framing (same algorithms as AuroraConnection.cs) against the Java match server.
using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

static class AuroraInterop
{
    static NetworkStream stream;

    static int Main(string[] args)
    {
        string host = args[0];
        int port = int.Parse(args[1]);
        string ticket = args[2];
        var client = new TcpClient(host, port);
        stream = client.GetStream();
        stream.ReadTimeout = 10000;

        var clientKey = new RSACryptoServiceProvider(1024);
        var p = clientKey.ExportParameters(false);
        var init = new MemoryStream();
        WriteBytes(init, p.Modulus);
        WriteBytes(init, p.Exponent);
        Send(1004, init.ToArray());

        var challengePacket = Expect(1005);
        int offset = 0;
        byte[] modulus = ReadBytes(challengePacket, ref offset);
        byte[] exponent = ReadBytes(challengePacket, ref offset);
        byte[] encryptedChallenge = ReadBytes(challengePacket, ref offset);
        var serverKey = new RSACryptoServiceProvider();
        serverKey.ImportParameters(new RSAParameters { Modulus = modulus, Exponent = exponent });
        byte[] challenge = Decrypt(encryptedChallenge, clientKey);
        Console.WriteLine("challenge: " + Encoding.UTF8.GetString(challenge));
        var complete = new MemoryStream();
        WriteBytes(complete, Encrypt(challenge, serverKey));
        Send(1006, complete.ToArray());

        byte[] requestLogin = Decrypt(Expect(1007), clientKey);
        int types = BitConverter.ToInt32(requestLogin, 0);
        Console.WriteLine("supported login types: " + types);

        var login = new MemoryStream();
        WriteInt(login, 2); WriteInt(login, 3); WriteInt(login, 0); WriteInt(login, 0);
        WriteInt(login, 0x8);
        WriteString(login, "");
        WriteString(login, ticket);
        Send(1008, Encrypt(login.ToArray(), serverKey));

        Expect(1010);
        Console.WriteLine("logged in");
        byte[] items = Expect(464);
        Console.WriteLine("item list received, count " + BitConverter.ToInt32(items, 0));
        Console.WriteLine("OK");
        return 0;
    }

    static void Send(ushort id, byte[] body)
    {
        byte crc = 0;
        foreach (byte b in body) crc ^= b;
        var header = new MemoryStream();
        var w = new BinaryWriter(header);
        w.Write((uint)body.Length); w.Write(id); w.Write(crc); w.Write(uint.MaxValue); w.Write(uint.MaxValue);
        stream.Write(header.ToArray(), 0, 15);
        stream.Write(body, 0, body.Length);
    }

    static byte[] Expect(int id)
    {
        for (int i = 0; i < 64; i++)
        {
            byte[] header = ReadFully(15);
            int length = BitConverter.ToInt32(header, 0);
            int packetId = BitConverter.ToUInt16(header, 4);
            byte[] body = ReadFully(length);
            if (packetId == 1003)
            {
                int o = 0;
                throw new Exception("disconnected: " + Encoding.Unicode.GetString(ReadBytes(body, ref o)));
            }
            if (packetId == id) return body;
        }
        throw new Exception("packet " + id + " not received");
    }

    static byte[] ReadFully(int length)
    {
        byte[] data = new byte[length];
        int read = 0;
        while (read < length)
        {
            int n = stream.Read(data, read, length - read);
            if (n <= 0) throw new EndOfStreamException();
            read += n;
        }
        return data;
    }

    static void WriteInt(MemoryStream s, int v) { s.Write(BitConverter.GetBytes(v), 0, 4); }
    static void WriteBytes(MemoryStream s, byte[] v) { WriteInt(s, v.Length); s.Write(v, 0, v.Length); }
    static void WriteString(MemoryStream s, string v) { WriteBytes(s, Encoding.Unicode.GetBytes(v)); }

    static byte[] ReadBytes(byte[] data, ref int offset)
    {
        int length = BitConverter.ToInt32(data, offset);
        offset += 4;
        byte[] result = new byte[length];
        Array.Copy(data, offset, result, 0, length);
        offset += length;
        return result;
    }

    // Identical to AuroraConnection.Encrypt / Decrypt
    static byte[] Encrypt(byte[] plain, RSACryptoServiceProvider key)
    {
        int blockSize = key.KeySize / 8;
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

    static byte[] Decrypt(byte[] encrypted, RSACryptoServiceProvider key)
    {
        int blockSize = key.KeySize / 8;
        if (encrypted.Length == 0 || encrypted.Length % blockSize != 0)
            throw new CryptographicException("Encrypted data is not a multiple of " + blockSize + " bytes");
        using (var output = new MemoryStream(encrypted.Length))
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
