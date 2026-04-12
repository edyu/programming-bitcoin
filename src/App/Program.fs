[<EntryPoint>]
let main args =
    if args.Length > 0 && args[0] = "test" then
        Library.test_testnet ()
    else
        Library.test_mainnet ()
    // Library.test_testnet ()

    0 // return an integer exit code
