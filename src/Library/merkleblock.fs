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

type MerkleTree = private { mutable current_depth: int; mutable current_index: int; total: int; nodes: byte array option list list } with
    member this.Levels = this.nodes

    member this.Total = this.total

    member this.MaxDepth = calculate_max_depth this.total

    override this.ToString (): string = 
        let mutable result: string list = []
        for level in this.Levels do
            let nodes = [ for x in level ->
                            match x with
                            | None -> "None"
                            | Some h -> (helper.bytes_to_hex h)[0..7] + "..."
                        ]
            result <- String.Join(',', nodes) :: result
        String.Join('\n', result)

    static member Create (total: int) =
        let max_depth = calculate_max_depth total
        let mutable nodes = []
        for depth in [0..max_depth] do
            let num_items = int (Math.Ceiling (float total / 2.0 ** float(max_depth - depth)))
            let level_hashes = [ for i in 1 .. num_items -> None ]
            nodes <- level_hashes :: nodes
        { current_depth = 0; current_index = 0; total = total; nodes = nodes }
