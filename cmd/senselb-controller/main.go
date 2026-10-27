// Command senselb-controller is the entrypoint for the senselb load-balancer
// controller. It is intentionally minimal for now: the reconciliation
// initialisation, provider wiring and signal handling are added in later
// phases.
package main

import "fmt"

// version is stamped at build time via:
//
//	-ldflags "-X main.version=<version>"
//
// It defaults to "dev" for local builds.
var version = "dev"

func main() {
	fmt.Println("senselb-controller", version)
}
