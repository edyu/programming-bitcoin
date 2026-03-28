module block

open System.IO

type Block = private { version: uint32; prev_block: byte[]; merkle_root: byte[]; timestamp: uint32; bits: byte[]; nonce: byte[] } with
    member this.Version = this.version
    member this.PrevBlock = this.prev_block
    member this.MerkleRoot = this.merkle_root
    member this.Timestamp = this.timestamp
    member this.Bits = this.bits
    member this.Nonce = this.nonce

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

    static member Create(version, prev_block, merkle_root, timestamp, bits, nonce) =
        { version = version; prev_block = prev_block; merkle_root = merkle_root; timestamp = timestamp; bits = bits; nonce = nonce }

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


