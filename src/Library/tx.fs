module tx

open System.Collections.Generic
open System.IO
open System.Text

[<Literal>]
let SIGHASH_ALL = 1u
[<Literal>]
let SIGHASH_NONE = 2u
[<Literal>]
let SIGHASH_SINGLE = 3u

type TxIn = private { prev_tx: byte[]; prev_index: uint32; script_sig: script.Script; sequence: uint32 } with
    member this.PrevTx = this.prev_tx
    member this.PrevIndex = this.prev_index
    member this.ScriptSig = this.script_sig
    member this.Sequence = this.sequence
    member this.Serialize =
        let prev_index = helper.int_to_little_endian(uint64 this.prev_index, 4)
        let script = this.ScriptSig.Serialize
        let sequence = helper.int_to_little_endian(uint64 this.sequence, 4)
        Array.concat [ Array.rev this.prev_tx; prev_index; script; sequence ]
    override this.ToString (): string =
        $"{helper.bytes_to_hex this.prev_tx}:{this.prev_index}"
    static member Create(prev_tx, prev_index, ?script_sig0, ?sequence0) =
        let script_sig = defaultArg script_sig0 script.Script.Empty
        let sequence = defaultArg sequence0 0xffffffffu
        { prev_tx = prev_tx; prev_index = prev_index; script_sig = script_sig; sequence = sequence }
    static member Parse (stream: Stream) =
        let prev_tx = Array.zeroCreate<byte> 32
        let mutable bytesRead = stream.Read(prev_tx, 0, 32)
        let buffer4 = Array.zeroCreate<byte> 4
        bytesRead <- stream.Read(buffer4, 0, 4)
        let prev_index = uint32 <| helper.little_endian_to_int buffer4
        let script = script.Script.Parse stream
        bytesRead <- stream.Read(buffer4, 0, 4)
        let sequence = uint32 <| helper.little_endian_to_int buffer4
        TxIn.Create(Array.rev prev_tx, prev_index, script, sequence)

type TxOut = private { amount: uint64; script_pubkey: script.Script } with
    member this.Amount = this.amount
    member this.ScriptPubKey = this.script_pubkey
    member this.Serialize =
        let amount = helper.int_to_little_endian(this.amount, 8)
        let script = this.script_pubkey.Serialize
        Array.concat [ amount; script ]
    override this.ToString() =
        $"{this.amount}:{this.script_pubkey.ToString()}"
    static member Create (amount: uint64, script_pubkey: script.Script) =
        { amount = amount; script_pubkey = script_pubkey }
    static member Parse (stream: Stream) =
        let buffer8 = Array.zeroCreate<byte> 8
        let bytesRead = stream.Read(buffer8, 0, 8)
        let amount = helper.little_endian_to_int buffer8
        let script = script.Script.Parse stream
        TxOut.Create(amount, script)

type Tx = private { version: uint32; tx_ins: TxIn[]; tx_outs: TxOut[]; locktime: uint32; testnet: bool } with
    static member Command = Encoding.ASCII.GetBytes "tx"
    member this.Version = this.version
    member this.TxIns = this.tx_ins
    member this.TxOuts = this.tx_outs
    member this.Locktime = this.locktime
    member this.Testnet = this.testnet

    static member Create(version, tx_ins, tx_outs, locktime, ?testnet0) =
        let testnet = defaultArg testnet0 false
        { version = version; tx_ins = tx_ins; tx_outs = tx_outs; locktime = locktime; testnet = testnet }

    static member Parse (stream: Stream, ?testnet0) =
        let testnet = defaultArg testnet0 false
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
        Tx.Create(version, tx_ins, tx_outs, locktime, testnet)

    member this.hash =
        Array.rev <| helper.hash256 this.Serialize

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

    member this.IsCoinbase =
        this.TxIns.Length = 1 && this.TxIns[0].PrevIndex = 0xffffffffu && this.TxIns[0].PrevTx = Array.zeroCreate 32

    member this.CoinbaseHeight =
        if not this.IsCoinbase then None
        else match this.TxIns[0].ScriptSig.Program[0] with
                | op.Data bytes -> Some <| helper.little_endian_to_int bytes
                | _ -> None

module TxHelper =
    let cache = new Dictionary<string, Tx>()

    let url testnet = if testnet then "https://blockstream.info/testnet/api/"
                      else "https://blockchain.info"

    let fetch tx_id testnet fresh : Tx =
        if fresh || not (cache.ContainsKey tx_id) then
            let url = if testnet then $"{url true}/tx/{tx_id}/hex"
                      else $"{url false}/rawtx/{tx_id}?format=hex"
            let response = helper.get_async url |> Async.RunSynchronously
            let mutable raw = helper.bytes_from_hex response
            let stream = new MemoryStream(raw)
            let tx = Tx.Parse stream
            if tx.Id <> tx_id then
                failwith $"not the same id: {tx.Id} vs {tx_id}"
            cache.Add(tx_id, tx)
        cache.Item tx_id

    let get_prev_tx (tx_in: TxIn) (testnet: bool) : Tx =
        fetch (helper.bytes_to_hex <| tx_in.PrevTx) testnet false

    let get_output_value (tx_in: TxIn) (testnet: bool) : uint64 =
        let prev_tx = get_prev_tx tx_in testnet
        prev_tx.TxOuts[int tx_in.PrevIndex].Amount

    let get_script_pubkey (tx_in: TxIn) (testnet: bool) =
        let prev_tx = get_prev_tx tx_in testnet
        prev_tx.TxOuts[int tx_in.PrevIndex].ScriptPubKey

    let get_fee (tx: Tx) (testnet: bool) : uint64 =
        let mutable input = 0UL
        let mutable output = 0UL
        for tx_in in tx.TxIns do
            input <- input + get_output_value tx_in testnet
        for tx_out in tx.TxOuts do
            output <- output + tx_out.Amount
        input - output

    let sig_hash (tx: Tx) (index: int) (redeem_script: script.Script option) (testnet: bool) =
        let version = helper.int_to_little_endian(uint64 tx.Version, 4)
        let num_txins = helper.encode_varint <| uint64 tx.TxIns.Length
        let mutable tx_ins = [||]
        for i in [0..tx.TxIns.Length - 1] do
            let tx_in = tx.TxIns[i]
            let script_pubkey =
                if i = index then
                    match redeem_script with
                    | Some redeem_script -> redeem_script
                    | None -> get_script_pubkey tx_in testnet
                else script.Script.Empty
            let new_in = TxIn.Create(tx_in.PrevTx, tx_in.PrevIndex, script_pubkey, tx_in.sequence)
            tx_ins <- Array.concat [ tx_ins; new_in.Serialize ]
        let num_txouts = helper.encode_varint <| uint64 tx.TxOuts.Length
        let mutable tx_outs = [||]
        for tx_out in tx.TxOuts do
            tx_outs <- Array.concat [ tx_outs; tx_out.Serialize ]
        let locktime = helper.int_to_little_endian(uint64 tx.Locktime, 4)
        let hashtype = helper.int_to_little_endian(uint64 SIGHASH_ALL, 4)
        let s = Array.concat [ version; num_txins; tx_ins; num_txouts; tx_outs; locktime; hashtype ]
        helper.bigint_from_bytes <| helper.hash256 s

    let verify_input (tx: Tx) (index: int) (testnet: bool) =
        let tx_in = tx.TxIns[index]
        let script_pubkey = get_script_pubkey tx_in testnet
        let redeem_script = if script_pubkey.IsScriptHash then
                                match tx_in.ScriptSig.Program.Head with
                                    | op.Data redeem ->
                                        let raw_redeem = Array.concat [ helper.encode_varint <| uint64 redeem.Length; redeem ]
                                        use stream = new MemoryStream(raw_redeem)
                                        Some <| script.Script.Parse stream
                                    | _ -> failwith "verify_input: can't find redeem script"
                            else
                                None
        let z = sig_hash tx index redeem_script testnet
        let combined_script = tx_in.ScriptSig + script_pubkey
        let verified, _ = combined_script.Evaluate z
        verified

    let verify (tx: Tx) (testnet: bool) =
        if get_fee tx testnet < 0UL then
            false
        else
            let mutable verified = true
            for i in [0..tx.TxIns.Length - 1] do
                if verified then
                    let tx_in = tx.TxIns[i]
                    verified <- verify_input tx i testnet
            verified

    let sign_input (tx: Tx) (index: int) (private_key: ecc.PrivateKey) (testnet: bool) =
        let z = sig_hash tx index None testnet
        let der = (private_key.Sign z).Der
        let sigb = Array.concat [ der; helper.int_to_big_endian(int SIGHASH_ALL, 1) ]
        let secb = private_key.Point.Sec ()
        let secba = Array.concat [ helper.encode_varint <| uint64 secb.Length + 2UL; [| byte secb.Length |]; secb; [| 0xacuy |] ]
        let sigba = Array.concat [ helper.encode_varint <| uint64 sigb.Length + 1UL; [| byte sigb.Length |]; sigb ]
        let script_sig = script.Script.Create [ op.Data sigba; op.Data secba ]
        let mutable tx_ins = tx.TxIns
        let prev_in = tx_ins[index]
        let tx_in = TxIn.Create(prev_in.PrevTx, prev_in.PrevIndex, script_sig)
        tx_ins[index] <- tx_in
        let new_tx = Tx.Create(tx.Version, tx_ins, tx.TxOuts, tx.Locktime)
        verify_input new_tx index testnet, new_tx
