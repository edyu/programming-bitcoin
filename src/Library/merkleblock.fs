module merkleblock

open System
open System.Collections
open System.IO

let calculate_max_depth total =  int (Math.Ceiling (Math.Log2 <| float total))

type FullMerkleTree = private { nodes: byte array list list } with
    member this.Levels = this.nodes

    member this.Total = this.nodes[this.nodes.Length - 1].Length

    member this.MaxDepth = calculate_max_depth this.Total

    override this.ToString (): string =
        let mutable result: string list = []
        for level in this.Levels do
            let nodes = [for x in level -> (helper.bytes_to_hex x)[0..7] + "..."]
            result <- String.Join(',', nodes) :: result
        String.Join('\n', List.rev result)

    static member Create (hashes: byte array list) =
        let mutable nodes = [ hashes ]
        let total= nodes[nodes.Length - 1].Length
        let max_depth = calculate_max_depth total
        for depth in [1..max_depth] do
            nodes <- helper.merkle_parent_level nodes.Head :: nodes
        { nodes = nodes }

type MerkleTree = private { mutable current_depth: int; mutable current_index: int; total: int; mutable nodes: byte array list array } with
    member this.Nodes = this.nodes

    member this.Total = this.total

    member this.MaxDepth = calculate_max_depth this.total

    override this.ToString (): string =
        let mutable result: string list = []
        for i, level in Array.indexed this.Nodes do
            let nodes = [ for j, x in List.indexed level ->
                            let short = if Array.isEmpty x then "None" else (helper.bytes_to_hex x)[0..7] + "..."
                            if i = this.current_depth && j = this.current_index then
                                "*" + short + "*"
                            else
                                short
                        ]
            result <- String.Join(',', nodes) :: result
        String.Join('\n', List.rev result)

    static member Create (total: int) =
        let max_depth = calculate_max_depth total
        let mutable nodes = Array.zeroCreate (max_depth + 1)
        for i in [0..max_depth] do
            let num_items = int (Math.Ceiling (float total / 2.0 ** float(max_depth - i)))
            nodes[i] <- List.init num_items (fun _ -> [||])
        { current_depth = 0; current_index = 0; total = total; nodes = nodes }

    member this.up =
        this.current_depth <- this.current_depth - 1
        this.current_index <- this.current_index / 2

    member this.left =
        this.current_depth <- this.current_depth + 1
        this.current_index <- this.current_index * 2

    member this.right =
        this.current_depth <- this.current_depth + 1
        this.current_index <- this.current_index * 2 + 1

    member this.root =
        this.Nodes[0][0]

    member this.set_current_node value =
        let i = this.current_index
        let list = this.nodes[this.current_depth]
        this.Nodes[this.current_depth] <- helper.list_update i list value

    member this.get_current_node =
        this.Nodes[this.current_depth][this.current_index]

    member this.get_left_node =
        this.Nodes[this.current_depth + 1][this.current_index * 2]

    member this.get_right_node =
        this.Nodes[this.current_depth + 1][this.current_index * 2 + 1]

    member this.is_leaf =
        this.current_depth = this.MaxDepth

    member this.right_exists =
        this.Nodes[this.current_depth + 1].Length > this.current_index * 2 + 1

    member this.PopulateTree (flag_bits: byte array) (hashes: byte array list) =
        let mutable flag_bits = flag_bits
        let mutable hashes = hashes

        while Array.isEmpty this.root do
            if this.is_leaf then
                flag_bits <- flag_bits[1..]
                this.set_current_node hashes.Head
                hashes <- hashes.Tail
                this.up
            else
                let left_hash = this.get_left_node
                if Array.isEmpty left_hash then
                    let flag = flag_bits[0]
                    flag_bits <- flag_bits[1..]
                    if flag = 0uy then
                        this.set_current_node hashes.Head
                        hashes <- hashes.Tail
                        this.up
                    else
                        this.left
                else if this.right_exists then
                    let right_hash = this.get_right_node
                    if Array.isEmpty right_hash then
                        this.right
                    else
                        this.set_current_node <| helper.merkle_parent left_hash right_hash
                        this.up
                else
                    this.set_current_node <| helper.merkle_parent left_hash left_hash
                    this.up
        if hashes.Length <> 0 then
            failwith $"hashes not all consumed {hashes.Length}"
        for flag in flag_bits do
            if flag <> 0uy then
                failwith "flag bit not all consumed"

type MerkleBlock = private { version: uint32; prev_block: byte array; merkle_root: byte array; timestamp: uint32; bits: byte array; nonce: byte array; total: uint32; hashes: byte array list; flags: byte array } with
    member this.Version = this.version
    member this.PrevBlock = this.prev_block
    member this.MerkleRoot = this.merkle_root
    member this.Timestamp = this.timestamp
    member this.Bits = this.bits
    member this.Nonce = this.nonce
    member this.Total = this.total
    member this.Hashes = this.hashes
    member this.Flags = this.flags

    override this.ToString (): string =
        let mutable result = $"{this.total}\n"
        for h in this.hashes do
            result <- result + $"\t{helper.bytes_to_hex h}\n"
        result + $"{helper.bytes_to_hex this.flags}"

    static member Create(version, prev_block, merkle_root, timestamp, bits, nonce, total, hashes, flags) =
        { version = version; prev_block = prev_block; merkle_root = merkle_root; timestamp = timestamp; bits = bits; nonce = nonce; total = total; hashes = hashes; flags = flags }

    static member Parse (stream: Stream) =
        let buffer4 = Array.zeroCreate<byte> 4
        let mutable bytesRead = stream.ReadExactly buffer4
        let version = uint32 <| helper.little_endian_to_int buffer4
        let buffer32 = Array.zeroCreate<byte> 32
        stream.ReadExactly buffer32
        let prev_block = Array.rev buffer32
        stream.ReadExactly buffer32
        let merkle_root = Array.rev buffer32
        stream.ReadExactly buffer4
        let timestamp = uint32 <| helper.little_endian_to_int buffer4
        stream.ReadExactly buffer4
        let bits = Array.copy buffer4
        stream.ReadExactly buffer4
        let nonce = Array.copy buffer4
        stream.ReadExactly buffer4
        let total = uint32 <| helper.little_endian_to_int buffer4
        let num_hashes = int <| helper.read_varint stream
        let hashes = [ for _ in [1..num_hashes] -> 
                             stream.ReadExactly buffer32
                             Array.rev buffer32 
                     ]
        let flags_len = int <| helper.read_varint stream
        let flags = Array.zeroCreate<byte> flags_len
        stream.ReadExactly flags
        MerkleBlock.Create(version, prev_block, merkle_root, timestamp, bits, nonce, total, hashes, flags)

    member this.is_valid =
        let flag_bits = helper.bytes_to_bit_field this.flags 
        let hashes = [ for h in this.hashes -> Array.rev h ]
        let merkle_tree = MerkleTree.Create <| int this.Total
        merkle_tree.PopulateTree flag_bits hashes
        Array.rev merkle_tree.root = this.MerkleRoot
