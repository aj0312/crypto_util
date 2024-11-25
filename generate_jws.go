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

	// jsonData := []byte(`{"ver":"2.0.0","timestamp":"2024-11-25T13:47:07.999+05:30","txnid":"642d2aff-e43b-4bb9-9057-498dbb9696s5","ConsentDetail":{"consentStart":"2024-11-11T17:20:07.999+05:30","consentExpiry":"2025-01-01T00:00:00.000+05:30","consentMode":"STORE","fetchType":"PERIODIC","consentTypes":["PROFILE","TRANSACTIONS","SUMMARY"],"fiTypes":["DEPOSIT"],"DataConsumer":{"id":"Sven","type":"FIU"},"Customer":{"Identifiers":[{"type":"MOBILE","value":"9819794280"}]},"Purpose":{"code":"101","refUri":"https://api.rebit.org.in/aa/purpose/101.xml","text":"To provide your asset insights","Category":{"type":"Personal Finance"}},"FIDataRange":{"from":"2024-01-11T17:20:07.999+05:30","to":"2024-11-11T17:20:07.999+05:30"},"DataLife":{"unit":"YEAR","value":3},"Frequency":{"unit":"DAY","value":10}}}`)
	// jsonData := []byte(`{"ver":"2.0.0","timestamp":"2024-11-25T08:21:36.491Z","txnid":"fdc66j2b-03e3-4df1-b8a2-22744a21183g","consentId":"32c66a98-7e20-41d6-9e9a-a5b387e2373a"}`)
	// jsonData := []byte(`{"ver":"2.0.0","timestamp":"2024-11-25T09:01:39.112Z","txnid":"f9cn9386-4689-4065-a473-2bra1e3168lb","FIDataRange":{"from":"2024-05-05T00:00:00.000Z","to":"2024-11-07T00:00:00.000Z"},"Consent":{"id":"32c66a98-7e20-41d6-9e9a-a5b387e2373a","digitalSignature":"ahfs7KEOYoqJGthZkQoeou8tR0ZvLdbz7nHZC13Cinsu3vzjQhPvPoPT-iWsD-skFfNmU7AW92Bjdtc5k7GSkAVF2q0suwb51Rb9VKPe78ElamvmMnZdOyXoOdEjhEmtQv0ZQSD4VlpHq-l-m_NFbcyYDoCpTmOwDXVSsSTwDE2exzmNZKQv6NiOHZpcl-WySz0qOUrJw6Sia7KadPUUsXjxo4l_KUdtTWhqkiflTWbLtmJxbSVXsVBnOub5tYh-i8hTPyJZ8yy2E94i4BNGJt0W6RR-2LucFhr6KI-TYO7JY5m2_QglrG1i4c_i_OzfT5KWP_z2GhT2GV79UcNniQ"},"KeyMaterial":{"cryptoAlg":"ECDH","curve":"Curve25519","params":"","DHPublicKey":{"expiry":"2024-11-26T08:48:38.189Z","Parameters":"","KeyValue":"-----BEGIN PUBLIC KEY-----MIIBMTCB6gYHKoZIzj0CATCB3gIBATArBgcqhkjOPQEBAiB/////////////////////////////////////////7TBEBCAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqYSRShRAQge0Je0Je0Je0Je0Je0Je0Je0Je0Je0Je0JgtenHcQyGQEQQQqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0kWiCuGaG4oIa04B7dLHdI0UySPU1+bXxhsinpxaJ+ztPZAiAQAAAAAAAAAAAAAAAAAAAAFN753qL3nNZYEmMaXPXT7QIBCANCAARwVVfAEBNvUYTIBJveTfM2Cs2icAAXftRDayrk9u+L2By6Lbidj0GoU7iaM4IYQ6FJD0fu59NQxxuNtB/KXOhc-----END PUBLIC KEY-----"},"Nonce":"RkrdU+31jZQyOrY4paysbdV4uGNMcKCSWnQNuphjdq4="}}`)
	jsonData := []byte(`{"ver":"2.0.0","timestamp":"2024-11-25T09:03:39.112Z","txnid":"f576daf8-f5fc-4968-86n5-ca14f5b1y3b1","sessionId":"a9cf8fe8-15ef-4fd1-85d2-238661fc6e86","fipId":"FIP-SIMULATOR","linkRefNumber":[{"id":"a45ab990-edce-4a71-9ec6-fbb27722701c"}]}`)

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
