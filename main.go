package main

import (
	"GoRottenTomato/module"
	"os"
)

func main()  {
	module.Parse(os.Args[1:])
}


