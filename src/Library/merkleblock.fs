module merkleblock

open System

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
