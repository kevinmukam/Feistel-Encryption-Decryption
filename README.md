# Feistel-Encryption-Decryption
The Python program shows Feistel cipher encryption/decryption, which takes as input a stream of bytes, a number of encryption rounds and a seed, and does the encryption/decryption. Several functions are written to attain the objective. Feistel encryption is used today in 3DES and AES encryption. 

For the Encryption process, the input is a plaintext, which is split into two equal parts. The right input will become the left output (for the following round), and the left input goes through an XOR operation with a value which is obtained from the right input and a key, applied in a round function as shown in the image below. 

The decryption process is simply the reverse. The value obtained at Round 15 in the encryption process will be the same value obtained at Round 1 in the decryption process. 

![One Block of Feistel](https://user-images.githubusercontent.com/68347909/110056249-73d05c00-7d2c-11eb-8864-4c101fb5f573.png)



The image above shows one block of Feistel encryption/decryption. The overall process is repeated a certain number of times as shown below. 

![Feistel Encryption   Decryption](https://user-images.githubusercontent.com/68347909/110056516-f78a4880-7d2c-11eb-983a-eb9de59c72c2.png)


