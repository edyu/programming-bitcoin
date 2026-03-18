open System
open Library

[<EntryPoint>]
let main args =
    let field = [ 0 .. 18 ]
    let ks = [ 1; 3; 7; 13; 18 ]
    let fields = [ for k in ks -> List.map (fun x -> (x * k) % 19) field ]

    for f in fields do
        printfn "%A" (List.sort f)

    let field2 = [ 0 .. 19 ]
    let ks2 = [ 1; 3; 7; 13; 18; 6; 4; 10 ]
    let fields2 = [ for k in ks2 -> List.map (fun x -> (x * k) % 20) field2 ]

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
    printfn "%A ** 3 == %A: %b" d f ((d *^ 3) = f)
    printfn "%A ** 12 == %A" d (d *^ 12)
    printfn "%A ** 12 == %A" e (e *^ 12)
    printfn "%A ** -3 = %A == %A ** 9 = %A: %b" c (c *^ -3) c (c *^ 9) (c *^ -3 = c *^ 9)

    let g = FieldElement.Create 8 13
    printfn "%A ** -3 = %A == %A" a (a *^ -3) ((a *^ -3) = g)
    let da = FieldElement.Create 3 31
    let db = FieldElement.Create 24 31
    let dc = FieldElement.Create 17 31
    let dd = FieldElement.Create 4 31
    let de = FieldElement.Create 11 31
    // printfn "%A / %A = %A" da db (da / db)
    printfn "%A ** -3 = %A" dc (dc *^ -3)
    printfn "%A ** -4 * %A = %A" dd de ((dd *^ -4) * de)

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
        match (result.X, result.Y) with
            | (Some x, Some y) ->
                printfn $"{s}*(47,71)=({x.Num},{y.Num})"
            | (None, None) ->
                printfn $"{s}*(47,71)=(Inf,Inf)"
            | (_, _) ->
                printfn $"{s}*(47,71)=({result})"

    printfn "%s" (bigint_tohex(P))
    printfn "%s" (bigint_tohex(bigint(37)))
    // let sf = S256Field.Create 7
    // printfn $"{sf}"

    0 // return an integer exit code
