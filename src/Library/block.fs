module block

open System.IO

[<Literal>]
let TWO_WEEKS = 60u * 60u * 24u * 14u

let MAX_TARGET = bigint 0xffff * bigint.Pow(256, 0x1d - 3)

let GENESIS_BLOCK = helper.bytes_from_hex "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
let TESTNET_GENESIS_BLOCK = helper.bytes_from_hex "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18"
let LOWEST_BITS = helper.bytes_from_hex "ffff001d"

let bits_to_target (bits: byte array) =
    if bits.Length <> 4 then
        failwith "bits byte array is too big"
    let exponent = int bits[bits.Length - 1]
    let coefficient = helper.little_endian_to_bigint bits[0..(bits.Length - 2)]
    coefficient * bigint.Pow(256I, exponent - 3)

let target_to_bits (target: bigint) =
    let mutable raw_bytes = helper.bigint_to_bytes target
    raw_bytes <- raw_bytes |> Seq.skipWhile (fun x -> x = 0uy) |> Array.ofSeq
    let exponent, coefficient = if raw_bytes[0] > 0x7fuy then
                                    raw_bytes.Length + 1, Array.concat [ [| 0uy |]; raw_bytes[0..1] ]
                                else
                                    raw_bytes.Length, raw_bytes[0..2]
    Array.append (Array.rev coefficient) [| byte exponent |]

let calculate_new_bits (previous_bits: byte[]) (time_differential: uint32) : byte[] =
    let mutable time_differential = time_differential
    if time_differential > TWO_WEEKS * 4u then
        time_differential <- TWO_WEEKS * 4u
    if time_differential < TWO_WEEKS / 4u then
        time_differential <- TWO_WEEKS / 4u
    let mutable new_target = bits_to_target previous_bits * bigint time_differential / bigint TWO_WEEKS
    if new_target > MAX_TARGET then
        new_target <- MAX_TARGET
    target_to_bits new_target

type Block = private { version: uint32; prev_block: byte[]; merkle_root: byte[]; timestamp: uint32; bits: byte[]; nonce: byte[]; tx_hashes: byte array list } with
    member this.Version = this.version
    member this.PrevBlock = this.prev_block
    member this.MerkleRoot = this.merkle_root
    member this.Timestamp = this.timestamp
    member this.Bits = this.bits
    member this.Nonce = this.nonce
    member this.TxHashes = this.tx_hashes

    member this.bip9 =
        this.version >>> 29 = 1u
    member this.bip91 =
        this.version >>> 4 &&& 1u = 1u
    member this.bip141 =
        this.version >>> 1 &&& 1u = 1u

    member this.hash =
        Array.rev <| helper.hash256 this.Serialize

    member this.Id =
        helper.bytes_to_hex this.hash

    member this.Serialize =
        let version = helper.int_to_little_endian(uint64 this.Version, 4)
        let prev_block = Array.rev this.PrevBlock
        let merkle_root = Array.rev this.MerkleRoot
        let timestamp = helper.int_to_little_endian(uint64 this.Timestamp, 4)
        Array.concat [ version; prev_block; merkle_root; timestamp; this.Bits; this.Nonce ]

    static member Create(version, prev_block, merkle_root, timestamp, bits, nonce, ?tx_hashes0) =
        let tx_hashes = defaultArg tx_hashes0 []
        { version = version; prev_block = prev_block; merkle_root = merkle_root; timestamp = timestamp; bits = bits; nonce = nonce; tx_hashes = tx_hashes }

    static member Parse (stream: Stream) =
        let buffer4 = Array.zeroCreate<byte> 4
        let mutable bytesRead = stream.ReadExactly buffer4
        let version = uint32 <| helper.little_endian_to_int buffer4
        let buffer32 = Array.zeroCreate<byte> 32
        bytesRead <- stream.ReadExactly buffer32
        let prev_block = Array.rev buffer32
        bytesRead <- stream.ReadExactly buffer32
        let merkle_root = Array.rev buffer32
        bytesRead <- stream.ReadExactly buffer4
        let timestamp = uint32 <| helper.little_endian_to_int buffer4
        bytesRead <- stream.ReadExactly buffer4
        let bits = Array.copy buffer4
        bytesRead <- stream.ReadExactly buffer4
        let nonce = Array.copy buffer4
        Block.Create(version, prev_block, merkle_root, timestamp, bits, nonce)

    member this.target = bits_to_target this.Bits

    member this.difficulty =
        let lowest = bigint 0xffff * bigint.Pow(256I, 0x1d - 3)
        lowest / this.target

    member this.check_pow =
        let hash = helper.hash256 this.Serialize
        let proof = helper.little_endian_to_bigint hash
        proof < this.target

    member this.validate_merkle_root =
        let hashes = [ for h in this.tx_hashes -> Array.rev h ]
        let root = helper.merkle_root hashes
        Array.rev root = this.merkle_root
