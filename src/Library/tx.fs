module tx

open System.IO

type Script = { script: byte[] } with
    static member Empty =
        { script = [||] }
    static member Parse (stream: Stream) =
        let len = int <| helper.read_varint stream
        let buffer = Array.zeroCreate<byte> len
        let bytesRead = stream.Read(buffer, 0, len)
        { script = buffer }
    member this.Serialize =
        Array.concat [ helper.encode_varint <| uint64 this.script.Length; this.script ]
    override this.ToString() = helper.bytes_to_hex this.script

type TxIn = private { prev_tx: byte[]; prev_index: uint32; script_sig: Script; sequence: uint32 } with
    member this.PrevTx = this.prev_tx
    member this.PrevIndex = this.prev_index
    member this.ScriptSig = this.script_sig
    member this.Sequence = this.sequence
    member this.Serialize =
        let prev_index = helper.int_to_little_endian(uint64 this.prev_index, 4)
        let script = this.ScriptSig.Serialize
        let sequence = helper.int_to_little_endian(uint64 this.sequence, 4)
        Array.concat [ this.prev_tx; prev_index; script; sequence ]
    override this.ToString (): string =
        $"{helper.bytes_to_hex this.prev_tx}:{this.prev_index}"
    static member Create(prev_tx, prev_index, ?script_sig0, ?sequence0) =
        let script_sig = defaultArg script_sig0 Script.Empty
        let sequence = defaultArg sequence0 0xffffffffu
        { prev_tx = prev_tx; prev_index = prev_index; script_sig = script_sig; sequence = sequence }
    static member Parse (stream: Stream) =
        let prev_tx = Array.zeroCreate<byte> 32
        let mutable bytesRead = stream.Read(prev_tx, 0, 32)
        let buffer4 = Array.zeroCreate<byte> 4
        bytesRead <- stream.Read(buffer4, 0, 4)
        let prev_index = uint32 <| helper.little_endian_to_int buffer4
        let script = Script.Parse stream
        bytesRead <- stream.Read(buffer4, 0, 4)
        let sequence = uint32 <| helper.little_endian_to_int buffer4
        TxIn.Create(prev_tx, prev_index, script, sequence)

type TxOut = private { amount: uint64; script_pubkey: Script } with
    member this.Amount = this.amount
    member this.ScriptPubKey = this.script_pubkey
    member this.Serialize =
        let amount = helper.int_to_little_endian(this.amount, 8)
        let script = this.script_pubkey.Serialize
        Array.concat [ amount; script ]
    override this.ToString() =
        $"{this.amount}:{this.script_pubkey.ToString()}"
    static member Create (amount: uint64, script_pubkey: Script) =
        { amount = amount; script_pubkey = script_pubkey }
    static member Parse (stream: Stream) =
        let buffer8 = Array.zeroCreate<byte> 8
        let bytesRead = stream.Read(buffer8, 0, 8)
        let amount = helper.little_endian_to_int buffer8
        let script = Script.Parse stream
        TxOut.Create(amount, script)

type Tx = private { version: uint32; tx_ins: TxIn[]; tx_outs: TxOut[]; locktime: uint32; testnet: bool } with
    member this.Version = this.version
    member this.TxIns = this.tx_ins
    member this.TxOuts = this.tx_outs
    member this.Locktime = this.locktime
    member this.Testnet = this.testnet

    static member Create(version, tx_ins, tx_outs, locktime, ?testnet0) =
        let testnet = defaultArg testnet0 false
        { version = version; tx_ins = tx_ins; tx_outs = tx_outs; locktime = locktime; testnet = testnet }

    static member Parse (stream: Stream) =
        let buffer4 = Array.zeroCreate<byte> 4
        let mutable bytesRead = stream.Read(buffer4, 0, 4)
        let version = uint32 <| helper.little_endian_to_int buffer4
        let num_inputs = int <| helper.read_varint stream
        let tx_ins = Array.zeroCreate<TxIn> (int num_inputs)
        for i = 0 to num_inputs - 1 do
            tx_ins[i] <- TxIn.Parse stream
        let num_outputs = int <| helper.read_varint stream
        let tx_outs = Array.zeroCreate<TxOut> (int num_outputs)
        for i = 0 to num_outputs - 1 do
            tx_outs[i] <- TxOut.Parse stream
        let buffer8 = Array.zeroCreate<byte> 8
        bytesRead <- stream.Read(buffer8, 0, 8)
        let locktime = uint32 <| helper.little_endian_to_int buffer8
        Tx.Create(version, tx_ins, tx_outs, locktime)

    member this.hash =
        helper.hash256 this.Serialize

    member this.Id =
        helper.bytes_to_hex this.hash

    override this.ToString() =
        let mutable tx_ins = ""
        for i = 0 to this.tx_ins.Length - 1 do
            tx_ins <- tx_ins + this.tx_ins[i].ToString() + "\n"
        let mutable tx_outs = ""
        for i = 0 to this.tx_outs.Length - 1 do
            tx_outs <- tx_outs + this.tx_outs[i].ToString() + "\n"
        $"tx: {this.Id}\nversion: {this.Version}\ntx_ins:\n{tx_ins}tx_outs:\n{tx_outs}locktime: {this.Locktime}"

    member this.Serialize =
        let version = helper.int_to_little_endian(uint64 this.Version, 4)
        let num_txins = helper.encode_varint <| uint64 this.TxIns.Length
        let mutable tx_ins = [||]
        for tx_in in this.TxIns do
            tx_ins <- Array.concat [ tx_ins; tx_in.Serialize ]
        let num_txouts = helper.encode_varint <| uint64 this.TxOuts.Length
        let mutable tx_outs = [||]
        for tx_out in this.TxOuts do
            tx_outs <- Array.concat [ tx_outs; tx_out.Serialize ]
        let locktime = helper.int_to_little_endian(uint64 this.Locktime, 4)
        Array.concat [ version; num_txins; tx_ins; num_txouts; tx_outs; locktime ]
