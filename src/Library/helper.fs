module helper

open System
open System.Globalization
open System.IO
open System.Numerics
open System.Security.Cryptography
open System.Text
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

let hash256 (bytes: byte[]) =
    use sha256 = SHA256.Create()
    sha256.ComputeHash bytes |> sha256.ComputeHash

let hash256_string (input: string) =
    let bytes = Encoding.UTF8.GetBytes input
    hash256 bytes

let hash160 (input: byte[]) =
    use sha256 = SHA256.Create()
    let bytes = sha256.ComputeHash input
    let ripemd160 = RipeMD160Digest()
    let result = Array.zeroCreate 20
    ripemd160.BlockUpdate(bytes, 0, bytes.Length)
    ripemd160.DoFinal(result, 0) |> ignore
    result

let bytes_to_hex bytes =
    BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant()

let bytes_from_hex (hex: string) =
    Convert.FromHexString hex

let bigint_from_bytes bytes =
    bytes_to_hex bytes |> bigint_from_hex

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
