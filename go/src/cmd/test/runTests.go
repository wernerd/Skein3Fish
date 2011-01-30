package main

import (
    "fmt"
    )

func main() {
/*    fmt.Printf("Starting Threefish test\n")
    basicTest256()
    basicTest512()
    basicTest1024()    
    fmt.Printf("Threefish test done\n")
*/
    fmt.Printf("Starting Skein test\n")
    vectorTest(setUp())
    fmt.Printf("Skein test done\n")

}
