module script

open System.IO

type Script = private { program: op.Cmd list } with
    member this.Program = this.program

    override this.ToString() =
        let mapfunc = function
            | op.Code c -> op.code_names[c]
            | op.Data d -> helper.bytes_to_hex d
        let ops = List.map mapfunc this.program
        String.concat " " ops

    static member Empty =
        { program = [] }

    static member Create ?program0 =
        let program = defaultArg program0 List.Empty
        { program = program }

    static member Parse stream =
        let mutable length = helper.read_varint stream
        let mutable cmds = List.Empty
        while length > 0UL do
            let current = stream.ReadByte()
            length <- length - 1UL
            if current >= 1 && current <= 75 then
                let buffer = Array.zeroCreate<byte> current
                stream.ReadExactly buffer
                cmds <- op.Data buffer :: cmds
                length <- length - uint64 current
            else if current = int op.OP_PUSHDATA1 then
                let datalen = helper.little_endian_to_int <| [| byte(stream.ReadByte()) |]
                let buffer = Array.zeroCreate<byte> <| int datalen
                stream.ReadExactly buffer
                cmds <- op.Data buffer :: cmds
                length <- length - 1UL - datalen
            else if current = int op.OP_PUSHDATA2 then
                let datalen = helper.little_endian_to_int <| [| byte(stream.ReadByte()); byte(stream.ReadByte()) |]
                let buffer = Array.zeroCreate<byte> <| int datalen
                stream.ReadExactly buffer
                cmds <- op.Data buffer :: cmds
                length <- length - 2UL - datalen
            else
                cmds <- op.Code (byte current) :: cmds
        { program = List.rev cmds }

    member this.raw_serialize : byte[] =
        let mutable serialized = List.Empty
        for cmd in this.program do
            match cmd with
            | op.Code opcode ->
                serialized <- opcode :: serialized
            | op.Data bytes ->
                if bytes.Length > 0 && bytes.Length <= 75 then
                    serialized <- byte bytes.Length :: serialized
                else if bytes.Length > 75 && bytes.Length < 0x100 then
                    serialized <- op.OP_PUSHDATA1 :: serialized
                    serialized <- byte bytes.Length :: serialized
                else if bytes.Length >= 0x100 && bytes.Length <= 520 then
                    serialized <- op.OP_PUSHDATA2 :: serialized
                    serialized <- Array.toList(helper.int_to_big_endian(bytes.Length, 2)) @ serialized
                else failwith "cmd is too long"
                serialized <- Array.toList(Array.rev bytes) @ serialized
        Array.ofList <| List.rev serialized

    member this.Serialize : byte[] =
        let serialized = this.raw_serialize
        Array.concat [ helper.encode_varint <| uint64 serialized.Length; serialized ]

    static member (+) (self, other : Script) =
        { program = self.program @ other.program }

    member this.IsPublicKeyHash =
        if this.program.Length <> 5 then false
        else match this.program with
                | op.Code op.OP_DUP :: op.Code op.OP_HASH160 ::op.Data h160 :: op.Code op.OP_EQUALVERIFY :: op.Code op.OP_CHECKSIG :: [] when h160.Length = 20 -> true
                | _ -> false

    member this.IsScriptHash =
        if this.program.Length <> 3 then false
        else match this.program with
                | op.Code op.OP_HASH160 :: op.Data h160 :: op.Code op.OP_EQUAL :: [] when h160.Length = 20 -> true
                | _ -> false

    member this.IsWitnessPublicKeyHash =
        if this.program.Length <> 2 then false
        else match this.program with
                | op.Code op.OP_0 :: op.Data h160 :: [] when h160.Length = 20 -> true
                | _ -> false

    member this.IsWitnessScriptHash =
        if this.program.Length <> 2 then false
        else match this.program with
                | op.Code op.OP_0 :: op.Data h256 :: [] when h256.Length = 32 -> true
                | _ -> false

    member this.Address (?testnet0: bool) =
        let testnet = defaultArg testnet0 false
        if this.IsPublicKeyHash then
            let h160 = match this.program with
                        | _ :: _ ::op.Data d :: _ -> d
                        | _ -> failwith "can't find h160 public key hash"
            Script.h160_to_p2pkh_address(h160, testnet)
        else if this.IsScriptHash then
            let h160 = match this.program with
                        | _ :: op.Data d :: _ -> d
                        | _ -> failwith "can't find h160 script hash"
            Script.h160_to_p2sh_address(h160, testnet)
        else failwith "can't find any address hash"

    static member p2pkh_script (h160: byte array) =
        Script.Create [ op.Code op.OP_DUP; op.Code op.OP_HASH160; op.Data h160; op.Code op.OP_EQUALVERIFY; op.Code op.OP_CHECKSIG ]

    static member p2sh_script (h160: byte array) =
        Script.Create [ op.Code op.OP_HASH160; op.Data h160; op.Code op.OP_EQUAL ]

    // p2wpkh ScriptPubKey
    static member p2wpkh_script (h160: byte array) =
        Script.Create [ op.Code op.OP_0; op.Data h160 ]

    static member p2wsh_script (h256: byte array) =
        Script.Create [ op.Code op.OP_0; op.Data h256 ]

    member this.Evaluate(z, ?witness0: byte array list) =
        let witness = defaultArg witness0 []
        let mutable stack = op.Stack.Empty
        let mutable altstack = op.Stack.Empty
        let mutable ok = true
        let mutable cmds = this.program
        while ok && not cmds.IsEmpty do
            let cmd = cmds.Head
            cmds <- cmds.Tail
            match cmd with
            | op.Code opcode ->
                match opcode with
                | op.OP_IF | op.OP_NOTIF ->
                    let opfunc = op.code_if_functions[opcode]
                    let new_ok, newstack, newcmds = opfunc stack cmds
                    ok <- new_ok
                    stack <- newstack
                    cmds <- newcmds
                | op.OP_TOALTSTACK | op.OP_FROMALTSTACK ->
                    let opfunc = op.code_altstack_functions[opcode]
                    let new_ok, newstack, newaltstack = opfunc stack altstack
                    ok <- new_ok
                    stack <- newstack
                    altstack <- newaltstack
                | op.OP_CHECKSIG
                | op.OP_CHECKSIGVERIFY
                | op.OP_CHECKMULTISIG
                | op.OP_CHECKMULTISIGVERIFY ->
                    let opfunc = op.code_sig_functions[opcode]
                    let new_ok, newstack = opfunc stack z
                    ok <- new_ok
                    stack <- newstack
                | _ ->
                    let opfunc = op.code_functions[opcode]
                    let new_ok, newstack = opfunc stack
                    ok <- new_ok
                    stack <- newstack
            | op.Data bytes ->
                stack <- bytes :: stack
                match cmds with
                | op.Code op.OP_HASH160 :: op.Data h160 :: op.Code op.OP_EQUAL :: [] when h160.Length = 20 ->
                    cmds <- []
                    let new_ok, newstack = op.op_hash160 stack
                    ok <- new_ok
                    stack <- newstack
                    if ok then
                        stack <- h160 :: stack
                        let new_ok, newstack = op.op_equal stack
                        ok <- new_ok
                        stack <- newstack
                        if ok then
                            let new_ok, newstack = op.op_verify stack
                            ok <- new_ok
                            stack <- newstack
                            if ok then
                                let redeem_script = Array.concat [ helper.encode_varint <| uint64 bytes.Length; bytes ]
                                use stream = new MemoryStream(redeem_script)
                                let new_script = Script.Parse stream
                                cmds <- cmds @ new_script.program
                | _ -> () // do nothing
                match stack with
                // p2wpkh
                | h160 :: zero :: [] when op.decode_num zero = 0 && h160.Length = 20 ->
                    match witness with
                    | pubkey :: signature :: [] ->
                        cmds <- cmds @ [ op.Data signature; op.Data pubkey ]
                        cmds <- cmds @ Script.p2pkh_script(h160).program
                    | _ -> failwith "wrong format in p2wpkh"
                    stack <- []
                // p2wsh
                | h256 :: zero :: [] when op.decode_num zero = 0 && h256.Length = 32 ->
                    stack <- []
                    let tail = List.rev [ for x in witness.Tail -> op.Data x ]
                    cmds <- cmds @ tail
                    let raw_script = witness.Head
                    let s256 = helper.sha256 raw_script
                    if h256 <> s256 then
                        printfn $"bad sha256 {helper.bytes_to_hex h256} vs {helper.bytes_to_hex s256}"
                        ok <- false
                    let witness_bytes = Array.concat [ helper.encode_varint <| uint64 raw_script.Length; raw_script ]
                    use stream = new MemoryStream(witness_bytes)
                    let witness_script = Script.Parse stream
                    cmds <- cmds @ witness_script.program
                | _ -> ()  // do nothing
        if not ok || stack.IsEmpty then
            false, stack
        else if not stack.IsEmpty && op.decode_num stack.Head = 0 then
            false, stack
        else
            true, stack

    static member h160_to_p2pkh_address(h160: byte[], ?testnet0: bool) =
        let testnet = defaultArg testnet0 false
        let prefix = if testnet then [| 0x6fuy |] else [| 0x00uy |]
        helper.base58_checksum <| Array.concat [ prefix; h160 ]

    static member h160_to_p2sh_address(h160: byte[], ?testnet0: bool) =
        let testnet = defaultArg testnet0 false
        let prefix = if testnet then [| 0xc4uy |] else [| 0x05uy |]
        helper.base58_checksum <| Array.concat [ prefix; h160 ]
