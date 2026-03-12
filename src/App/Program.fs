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

    try
        FieldElement.Create -2 17 |> ignore 
    with
        | :? ArgumentException as e -> printfn "%s" e.Message

    try
        FieldElement.Create 19 17 |> ignore 
    with
        | :? ArgumentException as e -> printfn "%s" e.Message

    let p1 = Point.Create -1 -1 5 7
    try
        Point.Create -1 -2 5 7 |> ignore
    with
        | :? ArgumentException as e -> printfn "%s" e.Message

    let p2 = Point.Create -1 1 5 7
    printfn $"{p1} + {p2} = {p1 + p2}"
    
    let p3 = Point.Create 2 5 5 7
    printfn $"{p3} + {p1} = {p3 + p1}"

    printfn $"{p1} + {p1} = {p1 + p1}"

    0 // return an integer exit code
