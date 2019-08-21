package main

import (
	"fmt"

	"github.com/dedis/lago/bigint"
	"github.com/dedis/lago/crypto"
	"github.com/dedis/lago/encoding"
)

func main() {
	// Initialize the numbers we are going to encrypt.
	msg1 := bigint.NewInt(10)
	msg2 := bigint.NewInt(8)

	// Initializing the
	N := uint32(32)                                        // polynomial degree
	T := bigint.NewInt(10)                                 // plaintext moduli
	Q := bigint.NewInt(8380417)                            // ciphertext moduli
	BigQ := bigint.NewIntFromString("4611686018326724609") // big ciphertext moduli, used in homomorphic multiplication and should be greater than q^2
	fmt.Printf("Parameters: N=%v, T=%v, Q=%v\n", N, T.Int64(), Q.Int64())

	fmt.Println("=== Performing operations using homomorphic encryption===")
	// create FV context and generate keys
	fv := crypto.NewFVContext(N, *T, *Q, *BigQ)
	key := crypto.GenerateKey(fv)

	// encode messages for its lattice-baed encryption
	// Use encoder from context
	encoder := encoding.NewEncoder(fv)
	// Create plaintext containers
	plaintext1 := crypto.NewPlaintext(N, *Q, fv.NttParams)
	plaintext2 := crypto.NewPlaintext(N, *Q, fv.NttParams)
	// Encode messages
	encoder.Encode(msg1, plaintext1)
	encoder.Encode(msg2, plaintext2)

	// encrypt plainetexts
	fmt.Println("[*] Encrypting plaintexts")
	encryptor := crypto.NewEncryptor(fv, &key.PubKey)
	ciphertext1 := encryptor.Encrypt(plaintext1)
	ciphertext2 := encryptor.Encrypt(plaintext2)

	// evaluate ciphertexts
	fmt.Println("[*] Performing operations")
	evaluator := crypto.NewEvaluator(fv, &key.EvaKey, key.EvaSize)
	add_cipher := evaluator.Add(ciphertext1, ciphertext2)
	mul_cipher := evaluator.Multiply(add_cipher, ciphertext2)

	// decrypt ciphertexts
	fmt.Println("[*] Decrypting resulting ciphertexts (from operands and results)")
	decryptor := crypto.NewDecryptor(fv, &key.SecKey)
	output_plaintext1 := decryptor.Decrypt(ciphertext1)
	output_plaintext2 := decryptor.Decrypt(ciphertext2)
	add_plaintext := decryptor.Decrypt(add_cipher)
	mul_plaintext := decryptor.Decrypt(mul_cipher)

	// decode messages
	new_msg1 := new(bigint.Int)
	new_msg2 := new(bigint.Int)
	add_msg := new(bigint.Int)
	mul_msg := new(bigint.Int)
	encoder.Decode(new_msg1, output_plaintext1)
	encoder.Decode(new_msg2, output_plaintext2)
	encoder.Decode(add_msg, add_plaintext)
	encoder.Decode(mul_msg, mul_plaintext)

	fmt.Printf("%v + %v = %v\n", new_msg1.Int64(), new_msg2.Int64(), add_msg.Int64())
	fmt.Printf("(%v + %v) * %v = %v\n", new_msg1.Int64(), new_msg2.Int64(), msg2.Int64(), mul_msg.Int64())
	fmt.Println("=== Performing operations directly in plaintext, without encryption ===")
	csum := new(bigint.Int)
	cmul := new(bigint.Int)
	// Perform directly plaintext operations
	csum.Add(msg1, msg2)
	cmul.Mul(csum, msg2)
	fmt.Printf("%v + %v = %v\n", msg1.Int64(), msg2.Int64(), add_msg.Int64())
	fmt.Printf("(%v + %v) * %v = %v\n", new_msg1.Int64(), new_msg2.Int64(), msg2.Int64(), mul_msg.Int64())
}
