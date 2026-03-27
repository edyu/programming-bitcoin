module helper

open System
open System.Globalization
open System.IO
open System.Net.Http
open System.Numerics
open System.Security.Cryptography
open System.Text
open System.Threading.Tasks
open Org.BouncyCastle.Crypto.Digests

let private bigint_to_hex_internal (b: bigint) (prefix: bool) (lead: bool)=
    let s = b.ToString "x64"
    let len = String.length s
    let mutable ss = s.Substring(len-64, 64)
    if not lead then
        while ss.StartsWith "0" do
            ss <- ss[1..]
    if prefix then
        "0x" + ss
    else
        ss

let bigint_to_hex (b: bigint) = bigint_to_hex_internal b false true

let hex i = bigint_to_hex_internal i true false

let bigint_from_hex (hex: string) =
    let s = if hex[0..1] = "0x" then hex[2..] else hex
    let lead = System.Int32.Parse(s[0..1], NumberStyles.HexNumber)
    if lead >= 0x80 then // make sure it's positive
        BigInteger.Parse("0" + s, NumberStyles.HexNumber)
    else
        BigInteger.Parse(s, NumberStyles.HexNumber)

let sha1 (bytes: byte[]) =
    use sha1 = SHA1.Create()
    sha1.ComputeHash bytes

let sha256 (bytes: byte[]) =
    use sha256 = SHA256.Create()
    sha256.ComputeHash bytes

let ripemd160 (bytes: byte[]) =
    let ripemd160 = RipeMD160Digest()
    let result = Array.zeroCreate 20
    ripemd160.BlockUpdate(bytes, 0, bytes.Length)
    ripemd160.DoFinal(result, 0) |> ignore
    result

let hash256 (bytes: byte[]) =
    use sha256 = SHA256.Create()
    sha256.ComputeHash bytes |> sha256.ComputeHash

let hash256_string (input: string) =
    let bytes = Encoding.UTF8.GetBytes input
    hash256 bytes

let hash160 (bytes: byte[]) =
    use sha256 = SHA256.Create()
    sha256.ComputeHash bytes |> ripemd160

let num_to_big_endian (i: bigint) (len: int) =
    let result = Array.zeroCreate len
    let bytes = i.ToByteArray()
    let len = min bytes.Length len
    Array.Copy(bytes, result, len)
    Array.Reverse result
    result

let bytes_to_hex bytes =
    BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant()

let bytes_from_hex (hex: string) =
    Convert.FromHexString hex

let bigint_from_bytes (bytes: byte[]) =
    bytes_to_hex bytes |> bigint_from_hex

let little_endian_to_bigint (bytes: byte[]) =
    bigint_from_bytes <| Array.rev bytes

let bigint_to_bytes (i: bigint) =
    let result = Array.zeroCreate 32
    let bytes = i.ToByteArray()
    let len = min bytes.Length 32
    Array.Copy(bytes, result, len)
    Array.Reverse result
    result

let rand_bigint (max: bigint) =
    let b = RandomNumberGenerator.GetBytes 32
    if max <= 0I then
        bigint_from_bytes b
    else
        bigint_from_bytes b % max

let lstrip (bytes: byte[]) (pre: byte) : byte[] =
    let index = Array.FindIndex(bytes, fun b -> b <> pre)
    if index = -1 then
        Array.Empty()
    else
        bytes[index..]

[<Literal>]
let BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

let base58 (s: byte[]) =
    let mutable count = Array.FindIndex(s, fun b -> b <> 0uy)
    if count < 0 then count <- 0
    let mutable num = bigint_from_bytes s
    let prefix = String.replicate count "1"
    let mutable result = ""
    let mutable rem = 0I
    while num > 0I do
        let q, r = bigint.DivRem(num, 58)
        num <- q
        rem <- r
        result <- string BASE58_ALPHABET[int rem] + result
    prefix + result

let base58_checksum (s: byte[]) =
    base58 <| Array.concat [ s; (hash256 s)[0..3] ]

let decode_base58_checksum (s: string) =
    let mutable num : bigint = bigint.Zero
    for c in s do
        num <- num * bigint 58
        num <- num + bigint(BASE58_ALPHABET.IndexOf c)
    let combined = num_to_big_endian num 25
    let checksum = combined[combined.Length-4..]
    let hash = hash256 combined[..combined.Length-5]
    if hash[0..3] <> checksum then
        failwith $"bad address: {bytes_to_hex checksum} {bytes_to_hex hash[0..3]}"
    else
        combined[1..combined.Length-5]

let little_endian_to_int (bytes: byte[]) =
    if not BitConverter.IsLittleEndian then
        Array.Reverse bytes
    if bytes.Length = 8 then
        BitConverter.ToUInt64 bytes
    else if bytes.Length = 4 then
        uint64 <| BitConverter.ToUInt32 bytes
    else if bytes.Length = 2 then
        uint64 <| BitConverter.ToUInt16 bytes
    else if bytes.Length = 1 then
        uint64 <| bytes[0]
    else
        uint64 <| BitConverter.ToUInt64 bytes

let int_to_little_endian (i: uint64, n: int) =
    let result = Array.zeroCreate n
    let bytes = BitConverter.GetBytes i
    let len = min bytes.Length n
    Array.Copy(bytes, result, len)
    if not BitConverter.IsLittleEndian then
        Array.Reverse result
    result

let big_endian_to_int (bytes: byte[]) =
    let input = if BitConverter.IsLittleEndian then bytes |>  Array.rev else bytes
    if bytes.Length = 1 then
        int input[0]
    else if bytes.Length = 2 then
        int(BitConverter.ToUInt16 input)
    else if bytes.Length = 4 then
        int(BitConverter.ToUInt32 input)
    else if bytes.Length = 8 then
        int(BitConverter.ToUInt64 input)
    else
        let buffer : byte[] = Array.zeroCreate 4
        let len = min input.Length 4
        Array.Copy(input, 0, buffer, 0, len)
        int(BitConverter.ToUInt32 buffer)
    // let mutable result = 0
    // for c in bytes do
    //     result <- result <<< 8
    //     result <- result + int c
    // result

let int_to_big_endian (i: int, n: int) =
    let result = Array.zeroCreate n
    let bytes : byte[] =
        if n = 1 then
            [| byte i |]
        else if n = 2 then
            BitConverter.GetBytes(uint16 i)
        else if n = 4 then
            BitConverter.GetBytes(uint32 i)
        else if n = 8 then
            BitConverter.GetBytes(uint64 i)
        else
            BitConverter.GetBytes i
    let len = min bytes.Length n
    Array.Copy(bytes, result, len)
    if BitConverter.IsLittleEndian then
        Array.Reverse result
    result

let read_varint (s: Stream) : uint64 =
    let i = s.ReadByte()
    if i = 0xfd then
        let buffer = Array.zeroCreate<byte> 2
        s.ReadExactly buffer |> ignore
        little_endian_to_int buffer
    else if i = 0xfe then
        let buffer = Array.zeroCreate<byte> 4
        s.ReadExactly buffer |> ignore
        little_endian_to_int buffer
    else if i = 0xff then
        let buffer = Array.zeroCreate<byte> 8
        s.ReadExactly buffer |> ignore
        little_endian_to_int buffer
    else
        uint64 i

let encode_varint (i: uint64) =
    if i < 0xfdUL then
        [| byte i |]
    else if i <  0x10000UL then
        Array.concat [ [| 0xfduy |]; int_to_little_endian(i, 2) ]
    else if i < 0x100000000UL then
        Array.concat [ [| 0xfeuy |]; int_to_little_endian(i, 4) ]
    else
        Array.concat [ [| 0xffuy |]; int_to_little_endian(i, 8) ]

let get_async (url: string) =
    async {
        use client = new HttpClient()
        let! response = client.GetAsync url |> Async.AwaitTask
        response.EnsureSuccessStatusCode() |> ignore
        let! body = response.Content.ReadAsStringAsync() |> Async.AwaitTask
        return body
    }

let list_drop = List.skip

let list_remove i list = List.take i list @ List.skip (i + 1) list
