module script

type Script = private { program: op.Cmd list } with
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

    member this.Evaluate z =
        let mutable stack = op.Stack.Empty
        let mutable altstack = op.Stack.Empty
        let mutable state = true
        let mutable cmds = this.program
        while state && not cmds.IsEmpty do
            let cmd = cmds.Head
            cmds <- cmds.Tail
            match cmd with
            | op.Code opcode ->
                match opcode with
                | op.OP_IF | op.OP_NOTIF ->
                    let opfunc = op.code_if_functions[opcode]
                    let newstate, newstack, newcmds = opfunc stack cmds
                    state <- newstate
                    stack <- newstack
                    cmds <- newcmds
                | op.OP_TOALTSTACK | op.OP_FROMALTSTACK ->
                    let opfunc = op.code_altstack_functions[opcode]
                    let newstate, newstack, newaltstack = opfunc stack altstack
                    state <- newstate
                    stack <- newstack
                    altstack <- newaltstack
                | op.OP_CHECKSIG
                | op.OP_CHECKSIGVERIFY
                | op.OP_CHECKMULTISIG
                | op.OP_CHECKMULTISIGVERIFY ->
                    let opfunc = op.code_sig_functions[opcode]
                    let newstate, newstack = opfunc stack z
                    state <- newstate
                    stack <- newstack
                | _ ->
                    let opfunc = op.code_functions[opcode]
                    let newstate, newstack = opfunc stack
                    state <- newstate
                    stack <- newstack
            | op.Data bytes ->
                stack <- bytes :: stack

        if state && op.decode_num stack.Head = 0 then
            false, stack
        else
            true, stack
