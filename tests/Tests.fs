module Tests

open System
open Xunit
open Library
open ecc
open helper

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
        Assert.True(true)

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
    let z = bigint_from_hex("bc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423")
    let r = bigint_from_hex("37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6")
    let s = bigint_from_hex("8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec")
    let px = bigint_from_hex("04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574")
    let py = bigint_from_hex("82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4")
    let point = S256Point.Create px py
    Assert.True(point.Verify z { r = r; s = s })

[<Fact>]
let ``test verification of signature 1`` () =
    let z = bigint_from_hex("0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60")
    let r = bigint_from_hex("0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395")
    let s = bigint_from_hex("0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4")
    let px = bigint_from_hex("887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c")
    let py = bigint_from_hex("61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34")
    let point = S256Point.Create px py
    Assert.True(point.Verify z { r = r; s = s })

[<Fact>]
let ``test verification of signature 2`` () =
    let z = bigint_from_hex("0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d")
    let r = bigint_from_hex("0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c")
    let s = bigint_from_hex("0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6")
    let px = bigint_from_hex("887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c")
    let py = bigint_from_hex("61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34")
    let point = S256Point.Create px py
    Assert.True(point.Verify z { r = r; s = s })

[<Fact>]
let ``test signature`` () =
    let e = bigint_from_bytes <| hash256 "my secret"
    let pk = PrivateKey.Create e
    let k = bigint 1234567890
    let z = bigint_from_bytes <| hash256 "my message"
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
    Assert.True((c3 = u3))

[<Fact>]
let ``test signature serialization`` () =
    let r = bigint_from_hex "0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6" 
    let s = bigint_from_hex "0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec" 
    let sign = { r = r; s = s }
    let der = bytes_from_hex "3045022037206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c60221008ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec"
    Assert.True(sign.Der = der)
