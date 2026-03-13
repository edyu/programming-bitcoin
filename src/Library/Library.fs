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
        let bn = bigint(a.num)
        let nn = int((pown bn n) % bigint(a.prime))
        { num = nn; prime = a.prime }
    static member (/) (a, b: FieldElement) =
        if a.prime <> b.prime then
            failwith "Cannot divide two numbers in different Fields" 
        a * (b *^ -1)

type Point = private { x: int option; y: int option; a: int; b: int  } with
    member this.X = this.x
    member this.Y = this.y
    member this.A = this.a
    member this.B = this.b
    member this.isInfinity = this.x = None
    static member CreateInfinity A B =
        { x = None; y = None; a = A; b = B }
    static member Create X Y A B =
        if Y * Y <> X * X * X + A * X + B then
            invalidArg "x y" $"({X}, {Y}) is not on the curve"
        else
            { x = Some X; y = Some Y; a = A; b = B }
    static member (+) (self, other: Point) =
        if self.a <> other.a || self.b <> other.b then
            failwith $"Points {self}, {other} are not the same curve" 
        match self.x, self.y, other.x, other.y with
            | None, _, _, _ | _, None, _, _  -> other
            | _, _, None, _ | _, _, _, None -> self
            | Some x1, Some y1, Some x2, Some y2 when x1 = x2 && y1 <> y2 ->
                { x = None; y = None; a = self.a; b = self.b }
            | Some x1, Some y1, Some x2, Some y2 when x1 = x2 && y1 = y2 ->
                if y1 = 0 then
                    { x = None; y = None; a = self.a; b = self.b }
                else
                    let s = (3 * x1 * x1 + self.a) / (2 * y1)
                    let x = s * s - 2 * x1
                    let y = s * (x1 - x) - y1
                    { x = Some x; y = Some y; a = self.a; b = self.b }
            | Some x1, Some y1, Some x2, Some y2 ->
                let s = (y2 - y1) / (x2 - x1)
                let x = s * s - x1 - x2
                let y = s * (x1 - x) - y1
                { x = Some x; y = Some y; a = self.a; b = self.b }


