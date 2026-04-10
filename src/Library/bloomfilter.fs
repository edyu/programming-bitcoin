module bloomfilter

open System.Collections

[<Literal>]
let BIP37_CONSTANT = 0xfba4c795u

type BloomFilter = private { size: int; mutable bit_field: BitArray; function_count: int; tweak: uint32 } with
    static member Create (size, function_count, tweak) =
        { size = size; bit_field = BitArray(size * 8); function_count = function_count; tweak = tweak }

    member this.Add (item: byte array) =
        for i in [0..this.function_count - 1] do
            let seed = uint32 i * BIP37_CONSTANT + this.tweak
            let h = helper.murmur3 item seed
            let bit = int <| h % uint32 this.bit_field.Length
            this.bit_field.Set(bit, true)

    member this.FilterBytes =
        let bytes = Array.zeroCreate<byte> this.size
        this.bit_field.CopyTo(bytes, 0)
        bytes

    member this.FilterLoad(?flag0: byte) =
        let flag = defaultArg flag0 1uy
        let size = helper.encode_varint <| uint64 this.size
        let bytes = this.FilterBytes
        let function_count = helper.int_to_little_endian(uint64 this.function_count, 4)
        let tweak = helper.int_to_little_endian(uint64 this.tweak, 4)
        let flag = helper.int_to_little_endian(uint64 flag, 1)
        let payload = Array.concat [ size; bytes; function_count; tweak; flag ]
        network.GenericMessage.Create("filterload", payload)
