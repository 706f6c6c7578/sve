package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

const signatureHeader = "X-Ed25519-Sig: "
const edpubHeader = "X-Ed25519-Pub: "

func main() {
	commandIndex := 1

	if len(os.Args) < 2 {
		fmt.Println("Usage: sve <gk|s|v> <key file> < infile [> outfile]")
		return
	}

	command := os.Args[commandIndex]

	switch command {
	case "gk":
		publicKey, privateKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			log.Fatalf("Failed to generate key pair: %v", err)
		}

		publicKeyHex := hex.EncodeToString(publicKey)
		privateKeyHex := hex.EncodeToString(privateKey)

		publicKeyFile := "pubkey"
		privateKeyFile := "privkey"

		err = ioutil.WriteFile(publicKeyFile, []byte(publicKeyHex), 0644)
		if err != nil {
			log.Fatalf("Failed to save public key: %v", err)
		}

		err = ioutil.WriteFile(privateKeyFile, []byte(privateKeyHex), 0644)
		if err != nil {
			log.Fatalf("Failed to save private key: %v", err)
		}

		fmt.Println("Key pair generated and saved in pubkey and privkey")

	case "s":
		if len(os.Args) < commandIndex+2 {
			fmt.Println("Usage: sve s <private key file> < infile > outfile")
			return
		}

		keyFile := os.Args[commandIndex+1]

		privateKeyBytes, err := ioutil.ReadFile(keyFile)
		if err != nil {
			log.Fatalf("Failed to read private key file: %v", err)
		}

		privateKey, err := hex.DecodeString(string(privateKeyBytes))
		if err != nil {
			log.Fatalf("Failed to decode private key: %v", err)
		}

		// Generate public key from private key
		publicKey := privateKey[32:]
		publicKeyHex := hex.EncodeToString(publicKey)

		messageBytes, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("Failed to read the message from stdin: %v", err)
		}

		// Convert all line endings to LF
		messageBytes = bytes.ReplaceAll(messageBytes, []byte("\r\n"), []byte("\n"))
		messageBytes = bytes.ReplaceAll(messageBytes, []byte("\r"), []byte("\n"))

		// Convert all LF to CRLF
		messageBytes = bytes.ReplaceAll(messageBytes, []byte("\n"), []byte("\r\n"))

		pubKeyHeader := edpubHeader + publicKeyHex + "\r\n\r\n"
		messageWithPubKey := append([]byte(pubKeyHeader), messageBytes...)

		// Include header values in the message body
		messageToSign := appendHeaderValues(messageWithPubKey)

		signature := signMessage(privateKey, messageToSign)
		signatureHex := hex.EncodeToString(signature)

		header := signatureHeader + signatureHex[:64] + "\r\n " + signatureHex[64:] + "\r\n"
		
		// Prepend the header to the message
		messageWithHeader := append([]byte(header), messageWithPubKey...)

		fmt.Print(string(messageWithHeader))

	case "v":
		stat, _ := os.Stdin.Stat()
    		if (stat.Mode() & os.ModeCharDevice) != 0 {
        	    fmt.Println("Usage: sve v < message")
                    return
    		}

    		messageWithHeader, err := ioutil.ReadAll(os.Stdin)
    		if err != nil {
        	    log.Fatalf("Failed to read the message with signature from stdin: %v", err)
    		}

    		if len(messageWithHeader) == 0 {
        	    fmt.Println("Error: Empty input. Please provide a message to verify.")
        	    return
    		}

		// If present, remove the extra CRLF at the end of the message
		for strings.HasSuffix(string(messageWithHeader), "\r\n\r\n") {
			messageWithHeader = []byte(strings.TrimSuffix(string(messageWithHeader), "\r\n"))
		}

		// Split the headers from the body
		parts := strings.SplitN(string(messageWithHeader), "\r\n\r\n", 2)
		if len(parts) != 2 {
			log.Fatalf("Invalid message format: missing headers or body")
		}

		headers := parts[0]
		messageBody := parts[1]

		// Extract public key from headers
		publicKeyHex := extractPublicKey(headers)

		if publicKeyHex == "" {
			log.Fatalf("Invalid message format: missing public key header")
		}

		publicKey, err := hex.DecodeString(publicKeyHex)
		if err != nil {
			log.Fatalf("Failed to decode public key: %v", err)
		}

		// Extract signature (this part remains unchanged)
		var signatureHex string
		lines := strings.Split(headers, "\r\n")
		for i, line := range lines {
			if strings.HasPrefix(line, signatureHeader) {
				signatureHex = strings.TrimPrefix(line, signatureHeader)
				// If the line ends with a space, the signature is folded
				if i+1 < len(lines) && strings.HasPrefix(lines[i+1], " ") {
					signatureHex += strings.TrimSpace(lines[i+1])
				}
				break
			}
		}

		if signatureHex == "" {
			log.Fatalf("Invalid message format: missing signature header")
		}

		// Include header values in the message body
		messageToVerify := appendHeaderValues([]byte(headers + "\r\n\r\n" + messageBody))

		valid := verifySignature(publicKey, signatureHex, messageToVerify)
		if valid {
			fmt.Println("Signature is valid.")
		} else {
			fmt.Println("Signature is not valid.")
		}
	}
}

func signMessage(privateKey []byte, message []byte) []byte {
	return ed25519.Sign(privateKey, message)
}

func verifySignature(publicKey []byte, signatureHex string, message []byte) bool {
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		log.Fatalf("Failed to decode signature: %v", err)
	}

	return ed25519.Verify(publicKey, message, signature)
}

func appendHeaderValues(message []byte) []byte {
	parts := strings.SplitN(string(message), "\r\n\r\n", 2)
	if len(parts) < 2 {
		log.Fatalf("Lines must end with CRLF instead of LF.")
	}
	headers := parts[0]
	messageBody := parts[1]

	var headerValues []string
	lines := strings.Split(headers, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(line, edpubHeader) {
			headerValues = append(headerValues, strings.TrimPrefix(line, edpubHeader))
		}
	}

	return []byte(strings.Join(headerValues, "\r\n") + "\r\n" + messageBody)
}

func extractPublicKey(headers string) string {
	lines := strings.Split(headers, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(line, edpubHeader) {
			return strings.TrimPrefix(line, edpubHeader)
		}
	}
	return ""
}

