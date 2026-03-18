module Tests

open System
open Xunit
open Library

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
    Assert.True((7*p).isInfinity)

[<Fact>]
let ``test order of G is N`` () =
    Assert.True((N*G).isInfinity)

[<Fact>]
let ``test verification of signature`` () =
    let z = bigint_fromhex("bc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423")
    let r = bigint_fromhex("37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6")
    let s = bigint_fromhex("8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec")
    let px = S256Field.Create <| bigint_fromhex("04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574")
    let py = S256Field.Create <| bigint_fromhex("82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4")
    let point = S256Point.Create px py
    let s_inv = bigint.ModPow(s, (N-bigint(2)), N)
    let u = z * s_inv % N
    let v = r * s_inv % N
    let R = u * G + v * point
    match R.X with
        | (Some x) -> Assert.True(x.Num = r)
        | _ -> Assert.True(false)
