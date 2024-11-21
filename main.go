package main

import (
	"fmt"
	"time"
)

func main() {
	// payload, jws, err := GenerateJWS()
	// if err != nil {
	// 	fmt.Printf("There was some roblem generating JWS: %sn", err)
	// 	return
	// }
	// fmt.Println("Payload: ")
	// fmt.Println(payload)
	// fmt.Println("Detached JWS Signature:")
	// fmt.Println(jws)

	// PrintECDH()

	// Example usage
	params := DecryptParameters{
		OurPrivateKey:     "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCeHG27A2ZqwE4c\nOQJIa4CVDD25NwOPHUn44T3V6diR9bWn68ArWNmwwHde/ahFTC+kC1jSmc+D+qEa\nPFX+pLKpZg6IRv2xm5nBSYGgRE9AhUQcDqDLUvSED/L+yUcyPdpkC4cgU7ej30J+\n3NveFaiJwZaTkrwmGwGztWOBl1zoLXT82zR4CY46/CyRL1Kj4rZuaeUcpfADePRe\nMpsiGHVc7uquQ9o+BPnW3PfaVWLp6V0YlD+etIu8L9tz5JRbkOhanbVPbby85R0u\nNMitLB2PzHn7zpoVpEsGGNh6QFf8wThyCmJ2m4jnBSKnMv1tIvEBe7QUeSrjaWu4\nxjQZ0Uw3AgMBAAECggEAA5FyrIDEI+6ZFKv4sDe03Cg9kFt8ehNYIwS6R4SSfaDE\n67g3SwMjTojZaMxiqsWwYYxcAcy00S6ryhLIggmneokyFMM9YG+5hZIqGbrQ6wzW\n36c4273QhNZzTmqub6TTs+RKtWEOSOV187T6RUXJ2uoCguwR0O5VGIAkcb0/vIGY\n5hLX3cB9B1eVEnlqPX6hOf5Xxm0hWZVaJNg+Fy+KwfPHDdDoawLx6Z2CwPr4mzZ4\nXygMxGEZEQwXQJAQamFF081Ixgi2jrYLsNtZEax3InOHklH6kN2salOMGCpZAdP0\n2XsAUsEE9EZ+s3cqNgRFwGjicb2R/ZbOrTBCpNMsgQKBgQDu/eJvLBfFxDzr+gdO\nbx2KgkMSE/hFPev7tK+zj9DflQtCCg9tkco5mU5Jpp30PR0h/yqSmqBSYMK2YoQm\nYN0wEaLI/0qbBlSUoZIBwpiWucM+mpUlJHw5QOan4OSpdS6ps0jBSQ8NNxwGA6L5\nH/Vn97q0QXdmndAeREvq/BoLQQKBgQCpXQEW5GAUTnwFjpcwiGUnqRE6aJYqY3XT\nEUxkd9xHdWfl/FBsr80yuqDKgPZV5CxeIMheiCuDlmw6Pqvmi84qr0HKVRKV9MXG\niE1IjpKxxty+b1KTFigFTs8cDRQqbnsSvLSCPLir7aA+vpZ6JO/0lPsuy+hed6gk\nbvMhowbRdwKBgQDu1M71VHYJT/ulwr6MdmRqJ5UJOuWvpJrwdnfjlMQiu1p9y3nx\ngHE8MGVZGuXczzoO4GXWDipLSKEtDLSNed1xDR7FiMIwvBnIUtKLacF9VvSz2l1T\nueted+pJOGiqpA1Wz3DUn8Mn7LvXksjJ91MSbDGrs4S0Ct+Rb6UClp8cQQKBgBNV\nK3+qeBE5WEzmFvoSR8G8Odw5/hI+oj+CtP6u8/UwQLjvEVsmwjytMxeKmxP45Nul\n0FmCH714mUgYyVSa1uDmepMXHPUDKORdwLyskbA7bA1M9dcWa2EXuuqPz6J8VA4y\nfkRzm/z8NhOTe+fbeYyoyPdxjUfjTs1B4P0Q+AFHAoGBAL470JpVw7gceAMjq4Aj\nofw6pMdtSgeUgAnWTEiYRbmxMxMkkWvRwTcOJTdjty+z7pmP9tQOwkeje11Xx9+R\n3BtEOz+VkxH+YztuQGz44M/ucx4NeyLg2Bz1Le0AWE1X3lrojbJBOXippGu7rOUt\n5N7Yw0+dagKZeDZO0PqLU9mI\n-----END PRIVATE KEY-----\n",
		RemotePublicKey:   "-----BEGIN PUBLIC KEY-----\n...",
		Base64YourNonce:   "your-nonce-base64",
		Base64RemoteNonce: "remote-nonce-base64",
		Base64Data:        "encrypted-data-base64",
		Expiry:            "2024-12-31T23:59:59.999Z",
	}

	expiryTime, err := time.Parse(time.RFC3339Nano, params.Expiry)
	if err != nil || expiryTime.Before(time.Now()) {
		fmt.Println("Error: Expired or invalid key")
		return
	}

	privateKey, err := ParsePEMKey(params.OurPrivateKey, true)
	if err != nil {
		fmt.Println("Error parsing private key:", err)
		return
	}
	publicKey, err := ParsePEMKey(params.RemotePublicKey, false)
	if err != nil {
		fmt.Println("Error parsing public key:", err)
		return
	}

	response, err := Decrypt(privateKey.([]byte), publicKey.([]byte), params.Base64YourNonce, params.Base64RemoteNonce, params.Base64Data)
	if err != nil {
		fmt.Println("Decryption failed:", err)
		return
	}

	fmt.Printf("Decrypted Data: %s\n", response.Result)
}
