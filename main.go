package main

import "fmt"

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

	// 	base64RemoteNonce := "us4T7wFFNofyZOIjQEJ9y9rQkVkYusg0aLsGRsXI7RI="
	// 	base64YourNonce := "59l9mtGfB28q/XLRdSxmnElAOdnYLm8Vpzc2P9M7wF4="
	// 	encryptedData := `kHsgNj7tjqxqD4N+jNoo+d7yoiDHpf075olBFJnZaHPgZ4Nl9p1RWBt2sR/2r/dxHCH2RJy8Gka9OPrGuZgNsuv/QN5cwzjR4cOOwdKOH9Pmhxb8ih22B4/4szPxbJlaLHWCp3jDo+phJuBx8wfkwpdJQxnvywC3z4gMRLy2WL0mcdWby6IhlwV+OvN8Q7i0pqdEuRlIGxcbppe0TxTYDmmqaPPUS65y1Ykdk/KD2jn3hdF4xAQ4LAR0SFpUDIdPM2TVC2VxCQEWtDBj2Zh+9xDUosGnldx3pMlCZ/hsHqAyBlEO8cBq9LWdp2Sx2MdrdeeT16LPxAhf0xSESX1wUGAilXeHlAMz/LGDWUZketMREYjNgFj587arPf9hh/rL0ISWA0y3fm0+Bq4aiMxRBKxIqyh5OclYp6qcvfXad2Nv6jALP0XeN68W4prJoXONHEvToIkymGmUVofmGYSBU1aJ/hrgDNIQS5upVZ6VemHBInRyBm/Ry8vQGW6FwnjEUz1CxElOap892BEs1Nvnpgn6UQ3rAr5Jnchd0T8yNy+fFJTm+PL8odY9sLPO0qU8qdJ8sievA7/uKL/cH4LG/kH330vHo3QbBlN7JdnVtAJTUoQyMyl0LUMbdbDcwlHklGgtMaxFHvRplxcAY8VVjJcjZVKhxK5hsk3VjN5XMMSymoUpmGUIR8ZpJ/KzqFIybQyr6cVgDGYsoDawONZYWGFnVKzV3UXsqbzz2CxgSZWVJ4TULmLo8kWyUvAUMiOfEEMcPVi2dFFxsL94Tcwgn9MCQUlEhukCN3KcgDuLGqIqirh0oxE2rYn1kZwPOs4JyCLNXA8EnbYbtmNyDqoLWlgGTAntD9qoLRBlg8+ts6NOcIdo7MfM6xdKHr46xaIPVSCIUVyPyCKhyx4Xm3Y7rRfQamjEZA6ikY6Qo7eVJHM9CCdg5LjkQ2c+/fPjTjiJxF0jhPmI8craLqR6abZRJLfuNGhXrnOAlQaI4X9nPtTudVCu4yKpcSRPd81Ng08YOb3ejPXvcOzsIM8Av/PlltmLbD8bkMn6iel5jlbCZb6U3ONKq4xQ28JfdggmkLz9NKWDc1PMphCWJ8yQS9xiTO8O5VUE3mA3K44RCJzLN8+N+gazfTyOcBjllDTYgvDBOKL6HHN8YJZVugQzg9X8PI+oX/Bl9xJvGOxaaJJXGLmxbaChiPd1S3IDjsWN+YayGnW32t1IGbeiYXTKFzhxh6iN9/WBlLzPVkXyJlWEiHwl1oEKTWc0I7nRGg3JNpfDSRxEPDuMy6NgAjqoQAFSb0Nb84X1q5ThieEPKb25nMlTPYXP+/wJsISoJKOfZR3ugrJAWL1M8qqxoD0fGBSFLMxCH785hl/WJl1zue4BlTHUAT1HsH9SkzYqFvswxPbwJ7Nab4cJR4w76pAKourCcXove8z41Qys/zUjQZ08YQ==`
	// 	privateKey := `-----BEGIN PRIVATE KEY-----
	// X1xqds8hgaDgyRgL0kJzyk9aiS4wqj3bKVMZOf4hnXY=
	// -----END PRIVATE KEY-----`
	// 	remotePublicKey := `-----BEGIN PUBLIC KEY-----
	// XH31Q8DQii9jv223uJws2rNnr/JDFlLypXmMvqE4NUM=
	// -----END PUBLIC KEY-----`
	// 	expiry := "2024-11-26T10:25:53Z"

	// 	decrypted, err := Decrypt(base64RemoteNonce, base64YourNonce, encryptedData, privateKey, remotePublicKey, expiry)
	// 	if err != nil {
	// 		log.Fatalf("Decryption failed: %v", err)
	// 	}

	// 	fmt.Println("Decrypted data:", decrypted)

	// Example usage
	// params := DecryptParameters{
	// 	OurPrivateKey: `-----BEGIN PRIVATE KEY-----
	// fBtCI3pewRcJ4Ut937YxuS6LPTCfjHCevyKAxIl3XCY=
	// -----END PRIVATE KEY-----`,
	// 	RemotePublicKey: `-----BEGIN PUBLIC KEY-----
	// g7+wA5V4FzJIkeFWOh9mA78vPxs6sY8xG6WBZu2+b2Y=
	// -----END PUBLIC KEY-----`,
	// 	Base64YourNonce:   "Npqq4vOK3kDcbaqzbffO7EX06nIgdqe+ZJmZkrknLGU=",
	// 	Base64RemoteNonce: "jxt70MzwVQ0FyI4Ekmp1Tyo8TmvCBgiL9h6C3u/UbA4=",
	// 	Base64Data:        "FxuBKpXY9mUo+g2X73P51nRlbGeWlw==",
	// 	Expiry:            "2024-11-26T11:33:46.666Z",
	// }

	// _, err := time.Parse(time.RFC3339Nano, params.Expiry)
	// if err != nil {
	// 	// || expiryTime.Before(time.Now()) {
	// 	fmt.Println("Error: Expired or invalid key")
	// 	return
	// }

	// privateKey, err := ParsePEMKey(params.OurPrivateKey, true)
	// if err != nil {
	// 	fmt.Println("Error parsing private key:", err)
	// 	return
	// }
	// publicKey, err := ParsePEMKey(params.RemotePublicKey, false)
	// if err != nil {
	// 	fmt.Println("Error parsing public key:", err)
	// 	return
	// }

	// response, err := Decrypt(privateKey, publicKey, params.Base64YourNonce, params.Base64RemoteNonce, params.Base64Data)
	// if err != nil {
	// 	fmt.Println("Decryption failed:", err)
	// 	return
	// }

	// fmt.Printf("Decrypted Data: %s\n", response.Result)

	keyMaterialMap, _ := GenerateKeyMaterialWithDefault()

	fmt.Printf("KeyMaterial Map ---> %v\n", keyMaterialMap)
	// fmt.Printf("privateKey ---> %s\n", privateKey)

	// Generate keys and response
	// response, err := generateKeyMaterial()
	// if err != nil {
	// 	fmt.Printf("Error generating keys: %v\n", err)
	// 	return
	// }

	// // Marshal response to JSON
	// responseJSON, err := json.MarshalIndent(response, "", "  ")
	// if err != nil {
	// 	fmt.Printf("Error marshaling JSON: %v\n", err)
	// 	return
	// }

	// // Print JSON response
	// fmt.Println(string(responseJSON))

	// privateKeyPEM := `-----BEGIN PRIVATE KEY-----\r\nMC4CAQAwBQYDK2VwBCIEINLh8PUDaCA4xDutrTjKbNf/4v9N862J4cSQ0w8yMKAW\r\n-----END PRIVATE KEY-----\r\n`
	// publicKeyPEM := `-----BEGIN PUBLIC KEY-----\r\nzk+nAAgPyk4XsDLw1KehsBnSjbw/ByOrlkYJCo9ua+4=\r\n-----END PUBLIC KEY-----\r\n`

	// // Generate the shared secret
	// sharedSecret, err := GenerateSharedNonce(privateKeyPEM, publicKeyPEM)
	// if err != nil {
	// 	fmt.Println("Error:", err)
	// 	return
	// }

	// fmt.Printf("Shared Secret: %x\n", sharedSecret)

	// 	base64RemoteNonce := "us4T7wFFNofyZOIjQEJ9y9rQkVkYusg0aLsGRsXI7RI="
	// 	base64YourNonce := "59l9mtGfB28q/XLRdSxmnElAOdnYLm8Vpzc2P9M7wF4="
	// 	data := `<?xml version="1.0" encoding="UTF-8"?> <Account xmlns="http://api.rebit.org.in/FISchema/deposit" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://api.rebit.org.in/FISchema/deposit ../FISchema/deposit.xsd" linkedAccRef="f6b1482e-8f08-11e8-862a-02552b0d3c36" maskedAccNumber="XXXXXXX3468" version="1.2" type="deposit"> <Profile> <Holders type="JOINT"> <Holder name="" dob="2002-09-24" mobile="91729391923" nominee="NOT-REGISTERED" email="qw@gmail.com" pan="AAAPL1234C" ckycCompliance="true"/> </Holders> </Profile> <Summary currentBalance="" currency="" exchgeRate="" balanceDateTime="2004-04-12T13:20:00-05:00" type="CURRENT" branch="" facility="CC" ifscCode="" micrCode="" openingDate="" currentODLimit="" drawingLimit="" status="ACTIVE"> <Pending amount="20.0"/> </Summary> <Transactions startDate="2004-04-12" endDate="2004-04-12"> <Transaction txnId="" type="CREDIT" mode="ATM" amount="20.0" currentBalance="" transactionTimestamp="2004-04-12T13:20:00-05:00" valueDate="2004-04-12" narration="" reference=""/> </Transactions> </Account>`
	// 	privateKey := `-----BEGIN PRIVATE KEY-----
	// X1xqds8hgaDgyRgL0kJzyk9aiS4wqj3bKVMZOf4hnXY=
	// -----END PRIVATE KEY-----`

	// 	remotePublicKey := `-----BEGIN PUBLIC KEY-----
	// XH31Q8DQii9jv223uJws2rNnr/JDFlLypXmMvqE4NUM=
	// -----END PUBLIC KEY-----`

	// 	encrypted, err := Encrypt(base64RemoteNonce, base64YourNonce, privateKey, remotePublicKey, data)
	// 	if err != nil {
	// 		log.Fatalf("Encryption failed: %v", err)
	// 	}

	// 	fmt.Println("Encrypted data:", encrypted)
}
