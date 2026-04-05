open System
open System.IO
open Library
open ecc
open helper
open tx
open block
open network

[<EntryPoint>]
let main args =
    let field = [ 0 .. 18 ]
    let ks = [ 1; 3; 7; 13; 18 ]
    let fields = [ for k in ks -> List.map (fun x -> x * k % 19) field ]

    for f in fields do
        printfn "%A" (List.sort f)

    let field2 = [ 0 .. 19 ]
    let ks2 = [ 1; 3; 7; 13; 18; 6; 4; 10 ]
    let fields2 = [ for k in ks2 -> List.map (fun x -> x * k % 20) field2 ]

    for f in fields2 do
        printfn "%A" (List.sort f)

    let a = FieldElement.Create 7 13
    printfn "%O" a
    let b = FieldElement.Create 12 13
    let c = FieldElement.Create 6 13
    let d = FieldElement.Create 3 13
    let e = FieldElement.Create 10 13
    let f = FieldElement.Create 1 13
    printfn "%A" b
    printfn "a==b=%b" (a=b)
    printfn "a==a=%b" (a=a)
    printfn "num=%d, prime=%d" a.Num a.Prime
    printfn "%A + %A == %A: %b" a b c (a + b = c)
    printfn "%A - %A == %A: %b" d c e (d - c = e)
    printfn "%A * %A == %A: %b" d b e (d * b = e)
    printfn "%A ** 3 == %A: %b" d f (d *^ 3 = f)
    printfn "%A ** 12 == %A" d (d *^ 12)
    printfn "%A ** 12 == %A" e (e *^ 12)
    printfn "%A ** -3 = %A == %A ** 9 = %A: %b" c (c *^ -3) c (c *^ 9) (c *^ -3 = c *^ 9)

    let g = FieldElement.Create 8 13
    printfn "%A ** -3 = %A == %A" a (a *^ -3) (a *^ -3 = g)
    let da = FieldElement.Create 3 31
    let db = FieldElement.Create 24 31
    let dc = FieldElement.Create 17 31
    let dd = FieldElement.Create 4 31
    let de = FieldElement.Create 11 31
    // printfn "%A / %A = %A" da db (da / db)
    printfn "%A ** -3 = %A" dc (dc *^ -3)
    printfn "%A ** -4 * %A = %A" dd de (dd *^ -4 * de)

    try
        FieldElement.Create -2 17 |> ignore
    with
        | :? ArgumentException as e -> printfn "%s" e.Message

    try
        FieldElement.Create 19 17 |> ignore
    with
        | :? ArgumentException as e -> printfn "%s" e.Message

    let p1 = IntPoint.Create -1 -1 5 7
    try
        IntPoint.Create -1 -2 5 7 |> ignore
    with
        | :? ArgumentException as e -> printfn "%s" e.Message

    let p2 = IntPoint.Create -1 1 5 7
    printfn $"{p1} + {p2} = {p1 + p2}"

    let p3 = IntPoint.Create 2 5 5 7
    printfn $"{p3} + {p1} = {p3 + p1}"

    printfn $"{p1} + {p1} = {p1 + p1}"

    let a = FieldElement.Create 0 223
    let b = FieldElement.Create 7 223
    let x = FieldElement.Create 192 223
    let y = FieldElement.Create 105 223
    let p1 = Point.Create x y a b

    let prime = 223
    let a = FieldElement.Create 0 prime
    let b = FieldElement.Create 7 prime
    let x1 = FieldElement.Create 192 prime
    let y1 = FieldElement.Create 105 prime
    let p1 = Point.Create x1 y1 a b

    let x2 = FieldElement.Create 143 prime
    let y2 = FieldElement.Create 98 prime
    let p2 = Point.Create x2 y2 a b

    let x3 = FieldElement.Create 47 prime
    let y3 = FieldElement.Create 71 prime
    let p3 = Point.Create x3 y3 a b

    let x = FieldElement.Create 15 prime
    let y = FieldElement.Create 86 prime
    let p = Point.Create x y a b
    printfn $"{p+p+p+p+p+p+p}"
    printfn $"{1*p}"
    printfn $"{2*p}"
    printfn $"{7*p}"
    for s in [1..21] do
        let result = s * p3
        match result.X, result.Y with
            | Some x, Some y ->
                printfn $"{s}*(47,71)=({x.Num},{y.Num})"
            | None, None ->
                printfn $"{s}*(47,71)=(Inf,Inf)"
            | _, _ ->
                printfn $"{s}*(47,71)=({result})"

    let pk1 = PrivateKey.Create <| bigint 5000
    printfn "sec1.un=%A" (bytes_to_hex <| pk1.Point.Sec false)
    printfn "sec1=%A" (bytes_to_hex <| pk1.Point.Sec true)
    printfn "parsed1.u=%A" (S256Point.Parse <| pk1.Point.Sec false)
    printfn "parsed1.c=%A" (S256Point.Parse <| pk1.Point.Sec true)
    let pk2 = PrivateKey.Create <| bigint.Pow(2018, 5)
    printfn "sec2.un=%A" (bytes_to_hex <| pk2.Point.Sec false)
    printfn "sec2=%A" (bytes_to_hex <| pk2.Point.Sec true)
    printfn "parsed2.u=%A" (S256Point.Parse <| pk2.Point.Sec false)
    printfn "parsed2.c=%A" (S256Point.Parse <| pk2.Point.Sec true)
    let pk3 = PrivateKey.Create <| bigint_from_hex "0xdeadbeef12345"
    printfn "sec3=%A" (bytes_to_hex <| pk3.Point.Sec ())

    let r = bigint_from_hex "0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6"
    let s = bigint_from_hex "0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec"
    let sign = { r = r; s = s }
    printfn "der=%A" (bytes_to_hex sign.Der)
    printfn "58=%A" (base58 sign.Der)

    let pk1 = PrivateKey.Create <| bigint 5002
    let p1 = pk1.Point
    let p1ut = p1.Address(false, true)
    printfn $"{p1ut}"

    let pk1 = PrivateKey.Create <| bigint 5003
    let wif1 = pk1.Wif(true, true)
    printfn $"{wif1}"

    let bytes = bytes_from_hex "010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600"
    use stream = new MemoryStream(bytes)
    let tx1 = Tx.Parse stream
    let tx_serialized = tx1.Serialize
    printfn $"{bytes = tx_serialized}"

    // let bytes0 = bytes_from_hex "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"
    // use stream = new MemoryStream(bytes0)
    // let tx0 = Tx.Parse stream
    // printfn "%A" tx0
    // // printfn "fee=%A" (TxFetcher.get_fee tx0)

    // // let tx2 = TxFetcher.fetch "b6f6991d03df0e2e04dafffcd6bc418aac66049e2cd74b80f14ac86db1e3f0da" false
    // let tx2 = TxFetcher.fetch "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16" false
    // printfn "%A" tx2
    // printfn "fee=%A" (TxFetcher.get_fee tx2)

    // let tx3 = TxFetcher.fetch "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d" false
    // printfn "fee=%A" (TxFetcher.get_fee tx3)

    let z = bigint_from_hex "7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d"
    let secb = bytes_from_hex "04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34"
    let sigb = bytes_from_hex "3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601"
    let stack = [ secb; sigb ]
    let state, stack = op.op_checksig stack z
    printfn "%A %A" state stack

    let secba = Array.concat [ helper.encode_varint <| uint64 secb.Length + 2UL; [| byte secb.Length |]; secb; [| 0xacuy |] ]
    use stream_pubkey = new MemoryStream(secba)
    let script_pubkey = script.Script.Parse stream_pubkey
    let sigba = Array.concat [ helper.encode_varint <| uint64 sigb.Length + 1UL; [| byte sigb.Length |]; sigb ]
    use stream_sig = new MemoryStream(sigba)
    let script_sig = script.Script.Parse stream_sig
    let combined_script = script_sig + script_pubkey
    let eval, _ = combined_script.Evaluate z
    printfn "%A" eval

    let spk_bytes = bytes_from_hex "6e879169a77ca787"
    let input = Array.concat [ helper.encode_varint <| uint64 spk_bytes.Length; spk_bytes ]
    use stream = new MemoryStream(input)
    let script_pubkey = script.Script.Parse stream
    let c1 = bytes_from_hex "255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f57696474682032203020522f4865696768742033203020522f547970652034203020522f537562747970652035203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e6774682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1fffe017f46dc93a6b67e013b029aaa1db2560b45ca67d688c7f84b8c4c791fe02b3df614f86db1690901c56b45c1530afedfb76038e972722fe7ad728f0e4904e046c230570fe9d41398abe12ef5bc942be33542a4802d98b5d70f2a332ec37fac3514e74ddc0f2cc1a874cd0c78305a21566461309789606bd0bf3f98cda8044629a1"
    let c2 = bytes_from_hex "255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f57696474682032203020522f4865696768742033203020522f547970652034203020522f537562747970652035203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e6774682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1fffe017346dc9166b67e118f029ab621b2560ff9ca67cca8c7f85ba84c79030c2b3de218f86db3a90901d5df45c14f26fedfb3dc38e96ac22fe7bd728f0e45bce046d23c570feb141398bb552ef5a0a82be331fea48037b8b5d71f0e332edf93ac3500eb4ddc0decc1a864790c782c76215660dd309791d06bd0af3f98cda4bc4629b1"
    let c_header = helper.encode_varint <| uint64(c1.Length + c2.Length + 6)
    let c1_bytes = Array.concat [ [| 77uy |]; int_to_little_endian(uint64 c1.Length, 2); c1 ]
    let c2_bytes = Array.concat [ [| 77uy |]; int_to_little_endian(uint64 c2.Length, 2); c2 ]
    let ss_bytes = Array.concat [ c_header; c1_bytes; c2_bytes ]
    use stream = new MemoryStream(ss_bytes)
    let script_sig = script.Script.Parse stream
    let combined_script = script_sig + script_pubkey
    printfn "combined: %A" combined_script
    let eval, stack =  combined_script.Evaluate 0
    printfn "%A %A" eval stack

    let bytes = decode_base58_checksum "mvm74FACaagz94rjWbNmW2EmhJdmEGcxpa"
    let hex = bytes_to_hex bytes
    let prev_tx = bytes_from_hex "0d6fe5213c0b3291f208cba8bfb59b7476dffacc4e5cb66f6eb20a080843a299"
    let prev_index = 13u
    let tx_in = TxIn.Create(prev_tx, prev_index)
    let tx_out = []
    let change_amount = 33000000UL
    let change_h160 = decode_base58_checksum "mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2"
    let change_script = script.p2pkh_script change_h160
    let change_output = TxOut.Create(change_amount, change_script)
    let target_amount = 10000000UL
    let target_h160 = decode_base58_checksum "mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf"
    let target_script = script.p2pkh_script target_h160
    let target_output = TxOut.Create(target_amount, target_script)
    let tx = Tx.Create(1u, [| tx_in |], [| change_output; target_output |], 0u)
    printfn "tx=%A" tx

    let last_bytes = bytes_from_hex "00000020fdf740b0e49cf75bb3d5168fb3586f7613dcc5cd89675b0100000000000000002e37b144c0baced07eb7e7b64da916cd3121f2427005551aeb0ec6a6402ac7d7f0e4235954d801187f5da9f5"
    use stream = new MemoryStream(last_bytes)
    let last_block = Block.Parse stream
    let first_bytes = bytes_from_hex "000000201ecd89664fd205a37566e694269ed76e425803003628ab010000000000000000bfcade29d080d9aae8fd461254b041805ae442749f2a40100440fc0e3d5868e55019345954d80118a1721b2e"
    use stream = new MemoryStream(last_bytes)
    let first_block = Block.Parse stream
    let time_differential = last_block.Timestamp - first_block.Timestamp
    let new_bits = calculate_new_bits (target_to_bits last_block.target) time_differential
    let new_target = bits_to_target new_bits
    printfn "%A" (bigint_to_hex new_target)

    let node = SimpleNode.Create("testnet.programmingbitcoin.com", 18333, true, true)
    // let command = node.Handshake
    // printfn "%A" command
    let version = VersionMessage.Create()
    node.Send (Version version)
    let mutable verack_received = false
    let mutable version_received = false
    while not verack_received && not version_received do
        let message = node.WaitFor [VersionMessage.Command; VerAckMessage.Command]
        match message with
        | VerAck _ -> verack_received <- true
        | Version _ -> version_received <- true
        | _ -> printfn "got %A" message

    0 // return an integer exit code
