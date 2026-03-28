module Tests

open System
open System.IO
open Xunit
open Library
open ecc
open helper
open script
open tx

[<Fact>]
let ``test curve valid points`` () =
    let prime = 223
    let a = FieldElement.Create 0 prime
    let b = FieldElement.Create 7 prime
    let valid_points = [(192, 105); (17, 56); (1, 193)]
    for x_raw, y_raw in valid_points do
        let x = FieldElement.Create x_raw prime
        let y = FieldElement.Create y_raw prime
        let p = Point.Create x y a b
        // if we reach next it means creation is successful
        Assert.True true

[<Fact>]
let ``test curve invalid points`` () =
    let prime = 223
    let a = FieldElement.Create 0 prime
    let b = FieldElement.Create 7 prime
    let invalid_points = [(200, 119); (42, 99)]
    for x_raw, y_raw in invalid_points do
        let x = FieldElement.Create x_raw prime
        let y = FieldElement.Create y_raw prime
        Assert.Throws<ArgumentException>(fun () -> Point.Create x y a b |> ignore) |> ignore

[<Fact>]
let ``test curve addition`` () =
    let prime = 223
    let a = FieldElement.Create 0 prime
    let b = FieldElement.Create 7 prime

    let x1 = FieldElement.Create 192 prime
    let y1 = FieldElement.Create 105 prime
    let x2 = FieldElement.Create 17 prime
    let y2 = FieldElement.Create 56 prime
    let p1 = Point.Create x1 y1 a b
    let p2 = Point.Create x2 y2 a b

    let x3 = FieldElement.Create 170 prime
    let y3 = FieldElement.Create 142 prime
    let p3 = Point.Create x3 y3 a b
    Assert.True(p1+p2=p3)

    let x4 = FieldElement.Create 60 prime
    let y4 = FieldElement.Create 139 prime
    let p4 = Point.Create x4 y4 a b

    let x5 = FieldElement.Create 220 prime
    let y5 = FieldElement.Create 181 prime
    let p5 = Point.Create x5 y5 a b
    Assert.True(p3+p4=p5)

    let x6 = FieldElement.Create 47 prime
    let y6 = FieldElement.Create 71 prime
    let p6 = Point.Create x6 y6 a b

    let x7 = FieldElement.Create 215 prime
    let y7 = FieldElement.Create 68 prime
    let p7 = Point.Create x7 y7 a b
    Assert.True(p6+p2=p7)

    let x8 = FieldElement.Create 143 prime
    let y8 = FieldElement.Create 98 prime
    let p8 = Point.Create x8 y8 a b

    let x9 = FieldElement.Create 76 prime
    let y9 = FieldElement.Create 66 prime
    let p9 = Point.Create x9 y9 a b
    Assert.True(p8+p9=p6)

[<Fact>]
let ``test curve scalar multiplication`` () =
    let prime = 223
    let a = FieldElement.Create 0 prime
    let b = FieldElement.Create 7 prime
    let x = FieldElement.Create 15 prime
    let y = FieldElement.Create 86 prime
    let p = Point.Create x y a b

    Assert.True(1*p=p)
    Assert.True((7*p).IsInfinity)

[<Fact>]
let ``test order of G is N`` () =
    Assert.True((N*S256Point.G).IsInfinity)

[<Fact>]
let ``test verification of signature`` () =
    let z = bigint_from_hex "bc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423"
    let r = bigint_from_hex "37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6"
    let s = bigint_from_hex "8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec"
    let px = bigint_from_hex "04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574"
    let py = bigint_from_hex "82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4"
    let point = S256Point.Create px py
    Assert.True(point.Verify z { r = r; s = s })

[<Fact>]
let ``test verification of signature 1`` () =
    let z = bigint_from_hex "0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60"
    let r = bigint_from_hex "0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395"
    let s = bigint_from_hex "0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4"
    let px = bigint_from_hex "887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c"
    let py = bigint_from_hex "61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34"
    let point = S256Point.Create px py
    Assert.True(point.Verify z { r = r; s = s })

[<Fact>]
let ``test verification of signature 2`` () =
    let z = bigint_from_hex "0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d"
    let r = bigint_from_hex "0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c"
    let s = bigint_from_hex "0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6"
    let px = bigint_from_hex "887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c"
    let py = bigint_from_hex "61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34"
    let point = S256Point.Create px py
    Assert.True(point.Verify z { r = r; s = s })

[<Fact>]
let ``test signature math`` () =
    let e = bigint_from_bytes <| hash256_string "my secret"
    let pk = PrivateKey.Create e
    let k = bigint 1234567890
    let z = bigint_from_bytes <| hash256_string "my message"
    let k_inv = bigint.ModPow(k, N - bigint 2, N)
    let r = (k * S256Point.G).X
    let s = (z + r * e) * k_inv % N
    Assert.True(pk.Point.Verify z { r = r; s = s})

[<Fact>]
let ``test private key signature`` () =
    let pk = PrivateKey.Create (rand_bigint N)
    let z = rand_bigint bigint.Zero // 2 ** 256
    let sign = pk.Sign z
    Assert.True(pk.Point.Verify z sign)

[<Fact>]
let ``test public key serialization`` () =
    let pk1 = PrivateKey.Create <| bigint 5000
    let pk1u = pk1.Point.Sec false
    let pk1c = pk1.Point.Sec ()
    let u1 = S256Point.Parse pk1u
    let c1 = S256Point.Parse pk1c
    Assert.True(pk1.Point = c1)
    Assert.True(pk1.Point = u1)
    let pk2 = PrivateKey.Create <| bigint.Pow(2018, 5)
    let pk2u = pk2.Point.Sec false
    let pk2c = pk2.Point.Sec ()
    let u2 = S256Point.Parse pk2u
    let c2 = S256Point.Parse pk2c
    Assert.True(pk2.Point = c2)
    Assert.True(pk2.Point = u2)
    let pk3 = PrivateKey.Create <| bigint_from_hex "0xdeadbeef12345"
    let pk3u = pk3.Point.Sec false
    let pk3c = pk3.Point.Sec ()
    let u3 = S256Point.Parse pk3u
    let c3 = S256Point.Parse pk3c
    Assert.True(pk3.Point = c3)
    Assert.True(pk3.Point = u3)

[<Fact>]
let ``test public key serialization 2`` () =
    let pk1 = PrivateKey.Create <| bigint 5001
    let pk1u = pk1.Point.Sec false
    let pk1c = pk1.Point.Sec ()
    let u1 = S256Point.Parse pk1u
    let c1 = S256Point.Parse pk1c
    Assert.True((c1 = u1))
    let pk2 = PrivateKey.Create <| bigint.Pow(2019, 5)
    let pk2u = pk2.Point.Sec false
    let pk2c = pk2.Point.Sec ()
    let u2 = S256Point.Parse pk2u
    let c2 = S256Point.Parse pk2c
    Assert.True((c2 = u2))
    let pk3 = PrivateKey.Create <| bigint_from_hex "0xdeadbeef54321"
    let pk3u = pk3.Point.Sec false
    let pk3c = pk3.Point.Sec ()
    let u3 = S256Point.Parse pk3u
    let c3 = S256Point.Parse pk3c
    Assert.True <| (c3 = u3)

[<Fact>]
let ``test signature serialization`` () =
    let r = bigint_from_hex "0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6"
    let s = bigint_from_hex "0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec"
    let sign = { r = r; s = s }
    let der = bytes_from_hex "3045022037206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c60221008ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec"
    Assert.True(sign.Der = der)
    Assert.True(sign.Der = der)

[<Fact>]
let ``test base58`` () =
    let h1 = "7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d"
    let h2 = "eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c"
    let h3 = "c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6"
    let h1b = bytes_from_hex h1
    let h2b = bytes_from_hex h2
    let h3b = bytes_from_hex h3
    let h158 = base58 h1b
    let h258 = base58 h2b
    let h358 = base58 h3b
    Assert.True <| (h158 = "9MA8fRQrT4u8Zj8ZRd6MAiiyaxb2Y1CMpvVkHQu5hVM6")
    Assert.True <| (h258 = "4fE3H2E6XMp4SsxtwinF7w9a34ooUrwWe4WsW1458Pd")
    Assert.True <| (h358 = "EQJsjkd6JaGwxrjEhfeqPenqHwrBmPQZjJGNSCHBkcF7")

[<Fact>]
let ``test address format`` () =
    let pk1 = PrivateKey.Create <| bigint 5002
    let p1 = pk1.Point
    let p1ut = p1.Address(false, true)
    Assert.True <| (p1ut = "mmTPbXQFxboEtNRkwfh6K51jvdtHLxGeMA")

    let pk2 = PrivateKey.Create <| bigint.Pow(2020, 5)
    let p2 = pk2.Point
    let p2ct = p2.Address(true, true)
    Assert.True <| (p2ct = "mopVkxp8UhXqRYbCYJsbeE1h1fiF64jcoH")

    let pk3 = PrivateKey.Create <| bigint_from_hex "0x12345deadbeef"
    let p3 = pk3.Point
    let p3cm = p3.Address ()
    Assert.True <| (p3cm = "1F1Pn2y6pDb68E5nYJJeba4TLg2U7B6KF1")

[<Fact>]
let ``test Wif format`` () =
    let pk1 = PrivateKey.Create <| bigint 5003
    let wif1 = pk1.Wif(true, true)
    Assert.True <| (wif1 = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN8rFTv2sfUK")

    let pk2 = PrivateKey.Create <| bigint.Pow(2021, 5)
    let wif2 = pk2.Wif(false , true)
    Assert.True <| (wif2 = "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjpWAxgzczjbCwxic")

    let pk3 = PrivateKey.Create <| bigint_from_hex "0x54321deadbeef"
    let wif3 = pk3.Wif ()
    Assert.True <| (wif3 = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgiuQJv1h8Ytr2S53a")

[<Fact>]
let ``test little endian`` () =
    let h1 = bytes_from_hex "99c3980000000000"
    Assert.True (little_endian_to_int h1 = 10011545UL)
    let h2 = bytes_from_hex "a135ef0100000000"
    Assert.True (little_endian_to_int h2 = 32454049UL)

    let n1 = 1UL
    Assert.True (int_to_little_endian(n1, 4) = [| 0x01uy; 0x00uy; 0x00uy; 0x00uy |])
    let n2 = 10011545UL
    Assert.True (int_to_little_endian(n2, 8) = [| 0x99uy; 0xc3uy; 0x98uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy |])
    let n3 = 10077080UL
    Assert.True (int_to_little_endian(n3, 4) = [| 0x98uy; 0xc3uy; 0x99uy; 0x00uy |])

[<Fact>]
let ``test transaction parsing and serialization`` () =
    let bytes = bytes_from_hex "010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600"
    use stream = new MemoryStream(bytes)
    let tx = Tx.Parse stream
    let tx_serialized = tx.Serialize
    Assert.True <| (bytes = tx_serialized)

[<Fact>]
let ``test transaction id`` () =
    let bytes = bytes_from_hex "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"
    use stream = new MemoryStream(bytes)
    let tx = Tx.Parse stream
    // first satoshi -> hal finney
    Assert.True <| (tx.Id = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16")

[<Fact>]
let ``test transaction fetch`` () =
    let tx = TxHelper.fetch "b6f6991d03df0e2e04dafffcd6bc418aac66049e2cd74b80f14ac86db1e3f0da" false
    Assert.True <| (tx.Id = "b6f6991d03df0e2e04dafffcd6bc418aac66049e2cd74b80f14ac86db1e3f0da")

// [<Fact>]
// let ``test transaction fee`` () =
//     let tx1 = TxHelper.fetch "b6f6991d03df0e2e04dafffcd6bc418aac66049e2cd74b80f14ac86db1e3f0da" true
//     Assert.True <| (TxHelper.get_fee tx1 = 0UL)
//     // pizza
//     let tx2 = TxHelper.fetch "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d" false
//     Assert.True <| (TxHelper.get_fee tx2 = 99000000UL)

[<Fact>]
let ``test big endian`` () =
    let h1 = bytes_from_hex "1000"
    Assert.True (big_endian_to_int h1 = 4096)
    let h2 = bytes_from_hex "99c398"
    Assert.True (big_endian_to_int h2 = 10077080)

    let n1 = 1
    Assert.True (int_to_big_endian(n1, 2) = [| 0x00uy; 0x01uy |])
    Assert.True (int_to_big_endian(n1, 1) = [| 0x01uy |])
    let n2 = 10077080
    Assert.True (int_to_big_endian(n2, 4) = [| 0x00uy; 0x99uy; 0xc3uy; 0x98uy |])
    Assert.True (int_to_big_endian(n2, 3) = [| 0x99uy; 0xc3uy; 0x98uy |])

[<Fact>]
let ``test script parsing and serialization`` () =
    let bytes = bytes_from_hex "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"
    use stream = new MemoryStream(bytes)
    let tx = Tx.Parse stream
    let s_bytes = tx.TxIns[0].ScriptSig.Serialize
    use stream = new MemoryStream(s_bytes)
    let s = script.Script.Parse stream
    let s_serialized = s.Serialize
    Assert.True <| (s_serialized = s_bytes)
    let s2_bytes = tx.TxOuts[0].ScriptPubKey.Serialize
    use stream = new MemoryStream(s2_bytes)
    let s2 = script.Script.Parse stream
    let s2_serialized = s2.Serialize
    Assert.True <| (s2_serialized = s2_bytes)
    let s3_bytes = tx.TxOuts[1].ScriptPubKey.Serialize
    use stream = new MemoryStream(s3_bytes)
    let s3 = script.Script.Parse stream
    let s3_serialized = s3.Serialize
    Assert.True <| (s3_serialized = s3_bytes)

[<Fact>]
let ``test script evaluation`` () =
    let z = bigint_from_hex "7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d"
    let secb = bytes_from_hex "04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34"
    let sigb = bytes_from_hex "3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601"
    let secba = Array.concat [ helper.encode_varint <| uint64 secb.Length + 2UL; [| byte secb.Length |]; secb; [| 0xacuy |] ]
    let sigba = Array.concat [ helper.encode_varint <| uint64 sigb.Length + 1UL; [| byte sigb.Length |]; sigb ]
    let script_sig = Script.Create [ op.Data sigba; op.Data secba ]
    let eval, _ = script_sig.Evaluate z
    Assert.True eval

[<Fact>]
let ``test op_checksig`` () =
    let z = bigint_from_hex "7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d"
    let secb = bytes_from_hex "04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34"
    let sigb = bytes_from_hex "3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601"
    let stack = [ secb; sigb ]
    let state, stack = op.op_checksig stack z
    Assert.True state
    Assert.True (op.decode_num <| List.head stack = 1)

[<Fact>]
let ``test op_hash160`` () =
    let bytes = System.Text.Encoding.UTF8.GetBytes "hello world"
    let stack = [ bytes ]
    let state, stack = op.op_hash160 stack
    Assert.True state
    Assert.True <| (List.head stack = helper.bytes_from_hex "d7d5ee7824ff93f94c3055af9382c86c68b5ca92")

[<Fact>]
let ``test op_if`` () =
    let bytes = bytes_from_hex "51635268"
    let input = Array.concat [ helper.encode_varint <| uint64 bytes.Length; bytes ]
    use stream = new MemoryStream(input)
    let script_if = script.Script.Parse stream
    let eval, stack = script_if.Evaluate 0
    Assert.True eval
    Assert.True <| (op.decode_num stack.Head = 2)

    let bytes = bytes_from_hex "516352675368"
    let input = Array.concat [ helper.encode_varint <| uint64 bytes.Length; bytes ]
    use stream = new MemoryStream(input)
    let script_if = script.Script.Parse stream
    let eval, stack = script_if.Evaluate 0
    Assert.True eval
    Assert.True <| (op.decode_num stack.Head = 2)

    let bytes = bytes_from_hex "006352675368"
    let input = Array.concat [ helper.encode_varint <| uint64 bytes.Length; bytes ]
    use stream = new MemoryStream(input)
    let script_if = script.Script.Parse stream
    let eval, stack = script_if.Evaluate 0
    Assert.True eval
    Assert.True <| (op.decode_num stack.Head = 3)

    let bytes = bytes_from_hex "51635163546868"
    let input = Array.concat [ helper.encode_varint <| uint64 bytes.Length; bytes ]
    use stream = new MemoryStream(input)
    let script_if = script.Script.Parse stream
    let eval, stack = script_if.Evaluate 0
    Assert.True eval
    Assert.True <| (op.decode_num stack.Head = 4)

[<Fact>]
let ``test op_notif`` () =
    let bytes = bytes_from_hex "00645268"
    let input = Array.concat [ helper.encode_varint <| uint64 bytes.Length; bytes ]
    use stream = new MemoryStream(input)
    let script_if = script.Script.Parse stream
    let eval, stack = script_if.Evaluate 0
    Assert.True eval
    Assert.True <| (op.decode_num stack.Head = 2)

    let bytes = bytes_from_hex "516452675368"
    let input = Array.concat [ helper.encode_varint <| uint64 bytes.Length; bytes ]
    use stream = new MemoryStream(input)
    let script_if = script.Script.Parse stream
    let eval, stack = script_if.Evaluate 0
    Assert.True eval
    Assert.True <| (op.decode_num stack.Head = 3)

[<Fact>]
let ``test simple scripts`` () =
    let bytes = bytes_from_hex "52767693935687"
    let input = Array.concat [ helper.encode_varint <| uint64 bytes.Length; bytes ]
    use stream = new MemoryStream(input)
    let script_if = script.Script.Parse stream
    let eval, stack = script_if.Evaluate 0
    Assert.True eval
    Assert.True <| (op.decode_num stack.Head <> 0)

    let code = bytes_from_hex "767693935687"
    let data = [| 1uy; 2uy |]
    let bytes = Array.concat [ data; code ]
    let input = Array.concat [ helper.encode_varint <| uint64 bytes.Length; bytes ]
    use stream = new MemoryStream(input)
    let script1 = script.Script.Parse stream
    let eval, stack = script1.Evaluate 0
    Assert.True eval
    Assert.True <| (op.decode_num stack.Head <> 0)

[<Fact>]
let ``test sha1 collision`` () =
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
    let eval, stack =  combined_script.Evaluate 0
    Assert.True eval
    Assert.True <| (op.decode_num stack.Head <> 0)

[<Fact>]
let ``test fee`` () =
    let raw_tx = bytes_from_hex "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
    use stream = new MemoryStream(raw_tx)
    let tx = Tx.Parse stream
    Assert.True (TxHelper.get_fee tx > 0UL)

[<Fact>]
let ``test signature`` () =
    let sec = bytes_from_hex "0349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a"
    let der = bytes_from_hex "3045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed"
    let z = bigint_from_hex "27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6"
    let point = S256Point.Parse sec
    let signature = Signature.Parse der
    Assert.True (point.Verify z signature)

[<Fact>]
let ``test sighash`` () =
    let raw_tx = bytes_from_hex "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
    use stream = new MemoryStream(raw_tx)
    let tx = Tx.Parse stream
    let sighash = TxHelper.sig_hash tx 0 None
    let result = bigint_from_hex "27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6"
    Assert.True <| (sighash = result)

[<Fact>]
let ``test verify_input`` () =
    let raw_tx = bytes_from_hex "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
    use stream = new MemoryStream(raw_tx)
    let tx = Tx.Parse stream
    Assert.True <| TxHelper.verify_input tx 0

[<Fact>]
let ``test verify`` () =
    let raw_tx = bytes_from_hex "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
    use stream = new MemoryStream(raw_tx)
    let tx = Tx.Parse stream
    Assert.True <| (TxHelper.verify tx)

[<Fact>]
let ``test transaction creation`` () =
    let prev_tx = bytes_from_hex "0d6fe5213c0b3291f208cba8bfb59b7476dffacc4e5cb66f6eb20a080843a299"
    let prev_index = 13u
    let tx_in = TxIn.Create(prev_tx, prev_index)
    let tx_out = []
    let change_amount = 33000000UL
    let change_h160 = decode_base58_checksum "mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2"
    let change_script = p2pkh_script change_h160
    let change_output = TxOut.Create(change_amount, change_script)
    let target_amount = 10000000UL
    let target_h160 = decode_base58_checksum "mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf"
    let target_script = p2pkh_script target_h160
    let target_output = TxOut.Create(target_amount, target_script)
    let tx = Tx.Create(1u, [| tx_in |], [| change_output; target_output |], 0u)
    Assert.True (tx.Id = "cd30a8da777d28ef0e61efe68a9f7c559c1d3e5bcd7b265c850ccb4068598d11")

// [<Fact>]
// let ``test transaction signing`` () =
    // let z = TxHelper.sig_hash tx 0 None
    // let private_key = PrivateKey.Create 8676309
    // let der = (private_key.Sign z).Der
    // let sigb = Array.concat [ der; int_to_big_endian(int SIGHASH_ALL, 1) ]
    // let sigba = Array.concat [ helper.encode_varint <| uint64 sigb.Length + 1UL; [| byte sigb.Length |]; sigb ]
    // let secb = private_key.Point.Sec ()
    // let secba = Array.concat [ helper.encode_varint <| uint64 secb.Length + 2UL; [| byte secb.Length |]; secb; [| 0xacuy |] ]
    // let script_sig = script.Script.Create [ op.Data sigba; op.Data secba ]
    // let tx_in = TxIn.Create(prev_tx, prev_index, script_sig)
    // let transaction = Tx.Create(1u, [| tx_in |], [| change_output; target_output |], 0u)
    // printfn $"{bytes_to_hex transaction.Serialize}"

[<Fact>]
let ``test new transaction creation`` () =
    let hash = hash256_string "Jimmy Song secret"
    let secret = little_endian_to_bigint <| hash256_string "Jimmy Song secret"
    let private_key = PrivateKey.Create secret
    Assert.True ((private_key.Point.Address(true, true) = "mn81594PzKZa9K3Jyy1ushpuEzrnTnxhVg"))

// [<Fact>]
// let ``test transaction creation 2`` () =
//     let prev_tx = bytes_from_hex "75a1c4bc671f55f626dda1074c7725991e6f68b8fcefcfca7b64405ca3b45f1c"
//     let prev_index = 1u
//     let tx_in = TxIn.Create(prev_tx, prev_index)
//     let change_amount = uint64(0.009*100000000.0)
//     let change_h160 = decode_base58_checksum "mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2"
//     printfn $"change_h160={bytes_to_hex change_h160}"
//     let change_script = TxHelper.p2pkh_script change_h160
//     let change_output = TxOut.Create(change_amount, change_script)
//     let target_amount = uint64(0.01*100000000.0)
//     let target_h160 = decode_base58_checksum "miKegze5FQNCnGw6PKyqUbYUeBa4x2hFeM"
//     printfn $"target_h160={bytes_to_hex target_h160}"
//     let target_script = TxHelper.p2pkh_script target_h160
//     let target_output = TxOut.Create(target_amount, target_script)
//     // let tx = Tx.Create(1u, [| tx_in |], [| change_output; target_output |], 0u)
//     let tx = Tx.Create(1u, [| tx_in |], [| target_output; change_output |], 0u)
//     let secret = 8675309
//     let priv = PrivateKey.Create secret
//     let signed, newtx = TxHelper.sign_input tx 0 priv
//     let serialized = bytes_to_hex newtx.Serialize
//     printfn $"signed\n{serialized}"
//     let bytes = "01000000011c5fb4a35c40647bcacfeffcb8686f1e9925774c07a1dd26f6551f67bcc4a175010000006b483045022100a08ebb92422b3599a2d2fcdaa11f8f807a66ccf33e7f4a9ff0a3c51f1b1ec5dd02205ed21dfede5925362b8d9833e908646c54be7ac6664e31650159e8f69b6ca539012103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b67ffffffff0240420f00000000001976a9141ec51b3654c1f1d0f4929d11a1f702937eaf50c888ac9fbb0d00000000001976a914d52ad7ca9b3d096a38e752c2018e6fbc40cdf26f88ac00000000"
//     printfn $"serialized.len={serialized.Length} compare.len={bytes.Length}"
//     Assert.True ((serialized = "01000000011c5fb4a35c40647bcacfeffcb8686f1e9925774c07a1dd26f6551f67bcc4a175010000006b483045022100a08ebb92422b3599a2d2fcdaa11f8f807a66ccf33e7f4a9ff0a3c51f1b1ec5dd02205ed21dfede5925362b8d9833e908646c54be7ac6664e31650159e8f69b6ca539012103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b67ffffffff0240420f00000000001976a9141ec51b3654c1f1d0f4929d11a1f702937eaf50c888ac9fbb0d00000000001976a914d52ad7ca9b3d096a38e752c2018e6fbc40cdf26f88ac00000000"))

[<Fact>]
let ``test p2sh address`` () =
    let h160 = bytes_from_hex "74d691da1574e6b3c192ecfb52cc8984ee7b6c56"
    let address = Script.h160_to_p2sh_address h160
    Assert.True ((address = "3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh"))

[<Fact>]
let ``test signature validation`` () =
    let hex_tx1 = "0100000001868278ed6ddfb6c1ed3ad5f8181eb0c7a385aa0836f01d5e4789e6bd304d87221a000000475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152aeffffffff04d3b11400000000001976a914904a49878c0adfc3aa05de7afad2cc15f483a56a88ac7f400900000000001976a914418327e3f3dda4cf5b9089325a4b95abdfa0334088ac722c0c00000000001976a914ba35042cfe9fc66fd35ac2224eebdafd1028ad2788acdc4ace020000000017a91474d691da1574e6b3c192ecfb52cc8984ee7b6c56870000000001000000"
    use stream = new MemoryStream(bytes_from_hex <| hex_tx1)
    let tx = Tx.Parse stream
    let z1 = bigint_from_bytes <| hash256 (bytes_from_hex hex_tx1)
    let sec1 = bytes_from_hex <| "022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb70"
    let der1 = bytes_from_hex <| "3045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a89937"
    let point1 = S256Point.Parse sec1
    let sig1 = Signature.Parse der1
    Assert.True (point1.Verify z1 sig1)

    let hex_tx = "0100000001868278ed6ddfb6c1ed3ad5f8181eb0c7a385aa0836f01d5e4789e6bd304d87221a000000db00483045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a8993701483045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e75402201475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152aeffffffff04d3b11400000000001976a914904a49878c0adfc3aa05de7afad2cc15f483a56a88ac7f400900000000001976a914418327e3f3dda4cf5b9089325a4b95abdfa0334088ac722c0c00000000001976a914ba35042cfe9fc66fd35ac2224eebdafd1028ad2788acdc4ace020000000017a91474d691da1574e6b3c192ecfb52cc8984ee7b6c568700000000"
    let hex_sec = "03b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb71"
    let hex_der = "3045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e754022"
    let hex_redeem_script = "475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152ae"
    let sec = bytes_from_hex hex_sec
    let der = bytes_from_hex hex_der
    use stream = new MemoryStream(bytes_from_hex <| hex_redeem_script)
    let redeem_script = Script.Parse stream
    use stream = new MemoryStream(bytes_from_hex <| hex_tx)
    let tx = Tx.Parse stream
    let mutable s = int_to_little_endian(uint64 tx.Version, 4)
    s <- Array.concat [ s; encode_varint <| uint64 tx.TxIns.Length ]
    let i = tx.TxIns[0]
    let txin = TxIn.Create(i.PrevTx, i.PrevIndex, redeem_script, i.Sequence)
    s <- Array.concat [ s; txin.Serialize ]
    s <- Array.concat [ s; encode_varint <| uint64 tx.TxOuts.Length ]
    for tx_out in tx.TxOuts do
        s <- Array.concat [ s; tx_out.Serialize ]
    s <- Array.concat [ s; int_to_little_endian(uint64 tx.Locktime, 4); int_to_little_endian(uint64 SIGHASH_ALL, 4) ]
    let z = bigint_from_bytes <| hash256 s
    Assert.True (bigint_to_hex z = "e71bfa115715d6fd33796948126f40a8cdd39f187e4afb03896795189fe1423c")
    let point = S256Point.Parse sec
    let sign = Signature.Parse der
    Assert.True (point.Verify z sign)

[<Fact>]
let ``test checking coinbase`` () =
    let txin = TxIn.Create(Array.zeroCreate 32, 0xffffffffu)
    let tx = Tx.Create(1u, [|txin|], [||], 0u)
    Assert.True tx.IsCoinbase
