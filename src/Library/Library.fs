module Library

//module ecc

type FieldElement = private { num: int; prime: int } with
    member this.Num = this.num
    member this.Prime = this.prime
    override this.ToString() = $"FieldElement_{this.Prime}({this.Num})"
    static member Create Num Prime =
        if Num >= Prime || Num  < 0 then
            invalidArg "Num" $"Num {Num} not in field range 0 to {Prime-1}"
        else
            { num = Num; prime = Prime }
    static member (+) (a, b: FieldElement) =
        if a.prime <> b.prime then
            failwith "Cannot add two numbers in different Fields" 
        { num = (a.num + b.num) % a.prime; prime = a.prime }
    static member (-) (a, b: FieldElement) =
        if a.prime <> b.prime then
            failwith "Cannot subtract two numbers in different Fields" 
        let d = (a.num - b.num + a.prime) % a.prime
        { num = d; prime = a.prime }
    static member (*) (a, b: FieldElement) =
        if a.prime <> b.prime then
            failwith "Cannot multiply two numbers in different Fields" 
        { num = (a.num * b.num) % a.prime; prime = a.prime }
    static member ( *^ ) (a: FieldElement, e) =
        let n = (e % (a.prime - 1) + (a.prime - 1)) % (a.prime - 1) 
        let nn = (pown a.num n) % a.prime
        { num = nn; prime = a.prime }
