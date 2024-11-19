package main

import "fmt"

func main() {
	payload, jws, err := GenerateJWS()
	if err != nil {
		fmt.Printf("There was some roblem generating JWS: %sn", err)
		return
	}
	fmt.Println("Payload: ")
	fmt.Println(payload)
	fmt.Println("Detached JWS Signature:")
	fmt.Println(jws)

	PrintECDH()
}
