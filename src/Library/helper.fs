module helper

open System
open System.Globalization
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
    let result = Array.create 20 0uy
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
    let result = Array.create 32 0uy
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
    BitConverter.ToInt32(bytes)

let int_to_little_endian (i: int, n: int) =
    let result = Array.create n 0uy
    let bytes = BitConverter.GetBytes i
    let len = min bytes.Length n
    Array.Copy(bytes, result, len)
    if not BitConverter.IsLittleEndian then
        Array.Reverse result
    result
