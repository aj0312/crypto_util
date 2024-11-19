package main

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

type Data struct {
	Ver           string `json:"ver"`
	Timestamp     string `json:"timestamp"`
	TxnId         string `json:"txnid"`
	ConsentHandle string `json:"ConsentHandle"`
}

func GenerateJWS() (string, string, error) {

	// jsonData := []byte(`{"ver":"2.0.0","timestamp":"2024-11-14T17:26:07.999+05:30","txnid":"644d2aff-e43b-4bb9-9057-498dbb9696s1","ConsentDetail":{"consentStart":"2024-11-11T17:20:07.999+05:30","consentExpiry":"2025-01-01T00:00:00.000+05:30","consentMode":"STORE","fetchType":"PERIODIC","consentTypes":["PROFILE","TRANSACTIONS","SUMMARY"],"fiTypes":["DEPOSIT"],"DataConsumer":{"id":"test-fiu-bank-1","type":"FIU"},"Customer":{"Identifiers":[{"type":"MOBILE","value":"9819794280"}]},"Purpose":{"code":"101","refUri":"https://api.rebit.org.in/aa/purpose/101.xml","text":"To provide your asset insights","Category":{"type":"Personal Finance"}},"FIDataRange":{"from":"2024-01-11T17:20:07.999+05:30","to":"2024-11-11T17:20:07.999+05:30"},"DataLife":{"unit":"YEAR","value":3},"Frequency":{"unit":"DAY","value":10}}}`)
	// jsonData := []byte(`{"ver":"2.0.0","timestamp":"2024-11-13T03:56:37.491Z","txnid":"fdc66g2b-03e3-4df1-b8a2-22744a21181h","consentId":"d5e8566d-ef47-4468-b9db-f42b0aa813ee"}`)
	jsonData := []byte(`{"ver":"2.0.0","timestamp":"2024-11-15T12:03:39.112Z","txnid":"f9cb9275-4689-4885-a463-2ada1e3028eb","FIDataRange":{"from":"2024-05-05T00:00:00.000Z","to":"2024-11-07T00:00:00.000Z"},"Consent":{"id":"b83e6b0e-b42e-42f0-9bc2-95826fb622b2","digitalSignature":"E2Dd7xOZJB4uAbVQ3Pjvq6jEotiwV5EvC-a0MgNMws3TaNaHCWoDpe998J36Lfau5jiitCMhdXLy63i8CSDmQAllgdg-oIJYgbgbLUhkT7rUtBsPlirEi6XxOORqSbh0Irx8SUNZhxJ1IE2-Bku7zIbPXdy3XDn-aN1aT3ExBYWKGHUf-hhr578fULp5L329acBJP6RBQWeYd7XG0HLLeWN-Uq--FCqgEDMA3iLoRRfz7aAecQA1rQpHbT1vUC4vTmDW07NkUHJcaDj9QPmf54zmAm_4I0FBHxk-xmA_fp7KOxs0egShHSmSijRCd6aMV3nRZ95wZ2GP562_3HFllA"},"KeyMaterial":{"cryptoAlg":"ECDH","curve":"X25519","params":"","DHPublicKey":{"expiry":"2024-11-16T12:00:41.999Z","Parameters":"","KeyValue":"-----BEGIN PUBLIC KEY-----\nznvgja2wklBlqb2DdPV4V/ie4eaBUJQEh473u/p+dng=\n-----END PUBLIC KEY-----\n"},"Nonce":"WiH0sbIbim9usCF/Duoxnz5kIk13liDV8MekT/3+txo="}}`)
	// jsonData := []byte(`{"ver":"2.0.0","timestamp":"2024-11-14T07:05:39.112Z","txnid":"f546daf6-f5fc-4968-81a5-ca14f5b1b3b1","sessionId":"2858be56-ddd7-406b-a700-53e6b2a271cd","fipId":"FIP-SIMULATOR","linkRefNumber":[{"id":"bfff1a17-2489-49f9-a1a8-07e642b067b7"}]}`)

	stringifiedPayload := string(jsonData)
	// Print the JSON data
	fmt.Println("Payload: ")
	fmt.Println(stringifiedPayload)

	const privateKeyJson = `{
	    "p": "7v3ibywXxcQ86_oHTm8dioJDEhP4RT3r-7Svs4_Q35ULQgoPbZHKOZlOSaad9D0dIf8qkpqgUmDCtmKEJmDdMBGiyP9KmwZUlKGSAcKYlrnDPpqVJSR8OUDmp-DkqXUuqbNIwUkPDTccBgOi-R_1Z_e6tEF3Zp3QHkRL6vwaC0E",
	    "kty": "RSA",
	    "q": "qV0BFuRgFE58BY6XMIhlJ6kROmiWKmN10xFMZHfcR3Vn5fxQbK_NMrqgyoD2VeQsXiDIXogrg5ZsOj6r5ovOKq9BylUSlfTFxohNSI6Sscbcvm9SkxYoBU7PHA0UKm57Ery0gjy4q-2gPr6WeiTv9JT7LsvoXneoJG7zIaMG0Xc",
	    "d": "A5FyrIDEI-6ZFKv4sDe03Cg9kFt8ehNYIwS6R4SSfaDE67g3SwMjTojZaMxiqsWwYYxcAcy00S6ryhLIggmneokyFMM9YG-5hZIqGbrQ6wzW36c4273QhNZzTmqub6TTs-RKtWEOSOV187T6RUXJ2uoCguwR0O5VGIAkcb0_vIGY5hLX3cB9B1eVEnlqPX6hOf5Xxm0hWZVaJNg-Fy-KwfPHDdDoawLx6Z2CwPr4mzZ4XygMxGEZEQwXQJAQamFF081Ixgi2jrYLsNtZEax3InOHklH6kN2salOMGCpZAdP02XsAUsEE9EZ-s3cqNgRFwGjicb2R_ZbOrTBCpNMsgQ",
	    "e": "AQAB",
	    "use": "sig",
	    "kid": "eY_FfQkKk2CfwJMwhmb-daOSd_ufWpgsoGNB4b9Bmrg",
	    "qi": "vjvQmlXDuBx4AyOrgCOh_Dqkx21KB5SACdZMSJhFubEzEySRa9HBNw4lN2O3L7PumY_21A7CR6N7XVfH35HcG0Q7P5WTEf5jO25AbPjgz-5zHg17IuDYHPUt7QBYTVfeWuiNskE5eKmka7us5S3k3tjDT51qApl4Nk7Q-otT2Yg",
	    "dp": "7tTO9VR2CU_7pcK-jHZkaieVCTrlr6Sa8HZ345TEIrtafct58YBxPDBlWRrl3M86DuBl1g4qS0ihLQy0jXndcQ0exYjCMLwZyFLSi2nBfVb0s9pdU7nrXnfqSThoqqQNVs9w1J_DJ-y715LIyfdTEmwxq7OEtArfkW-lApafHEE",
	    "alg": "RS256",
	    "dq": "E1Urf6p4ETlYTOYW-hJHwbw53Dn-Ej6iP4K0_q7z9TBAuO8RWybCPK0zF4qbE_jk26XQWYIfvXiZSBjJVJrW4OZ6kxcc9QMo5F3AvKyRsDtsDUz11xZrYRe66o_PonxUDjJ-RHOb_Pw2E5N759t5jKjI93GNR-NOzUHg_RD4AUc",
	    "n": "nhxtuwNmasBOHDkCSGuAlQw9uTcDjx1J-OE91enYkfW1p-vAK1jZsMB3Xv2oRUwvpAtY0pnPg_qhGjxV_qSyqWYOiEb9sZuZwUmBoERPQIVEHA6gy1L0hA_y_slHMj3aZAuHIFO3o99Cftzb3hWoicGWk5K8JhsBs7VjgZdc6C10_Ns0eAmOOvwskS9So-K2bmnlHKXwA3j0XjKbIhh1XO7qrkPaPgT51tz32lVi6eldGJQ_nrSLvC_bc-SUW5DoWp21T228vOUdLjTIrSwdj8x5-86aFaRLBhjYekBX_ME4cgpidpuI5wUipzL9bSLxAXu0FHkq42lruMY0GdFMNw"
	}`
	privateKey, err := jwk.ParseKey([]byte(privateKeyJson))
	if err != nil {
		fmt.Printf("failed parse key: %sn", err)
		return "", "", err
	}
	headers := jws.NewHeaders()
	headers.Set("b64", false)
	headers.Set("crit", []string{"b64"})

	serialized, err := jws.Sign(nil,
		jws.WithKey(jwa.RS256,
			privateKey,
			jws.WithProtectedHeaders(headers),
		),
		jws.WithDetachedPayload(jsonData),
	)
	if err != nil {
		fmt.Printf("failed to sign payload: %sn", err)
		return "", "", err
	}
	stringifiedJWS := string(serialized)
	fmt.Println("Detached JWS Signature:")
	fmt.Println(stringifiedJWS)

	return stringifiedPayload, stringifiedJWS, nil

}
