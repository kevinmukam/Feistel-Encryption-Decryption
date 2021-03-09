#Network Security
#Feistel Encryption/Decryption Algorithms
#March 3, 2021

Last_Name = "Mukam"
First_Name = "Kevin"

#------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------



#A  function to perform bitwise XOR on two byte sequences
def xor(byteseq1, byteseq2):
  #Python already provides the ^ operator to do xor on interger values
  #but first it's important to break the input byte sequences into bye size integers

  #Convert each byte sequence to a list
  l1 = [b for b in byteseq1]
  l2 = [b for b in byteseq2]
  l1attachl2 = zip(l1,l2)
  #zip(l1,l2) is actually a list as [(b'\xaa',b'\xcc), (b'\x33', b'\x55')]

  l1xorl2 = [bytes([elem1^elem2]) for elem1,elem2 in l1attachl2]

  result = b''.join(l1xorl2)

  return result


#------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------


#Feistel operation doesn't depend on the choice of the F function (its encryption strength does)
import hmac
import hashlib
import random

def F(byteseq, k):
  #The hmac hash
  h = hmac.new(k, byteseq, hashlib.sha1)

  #return the first 8 bytes of the hash value
  return h.digest()[:8]



#------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------


#In a real Feistel implementation, different keys are used in different rounds. Here
#there are 64bit keys so for 16 rounds, 16 random 8-byte keys are needed. I can generate
#16 random 8 byte numbers using the random function to be able to set the seed
#value and create the same keys for both the encoder and the decoder

def gen_keylist(keylenbytes, numkeys, seed):
    #Generate numkeys keys each being keylenbytes long
    keylist = []
    random.seed(seed)

    #Generate a list of numkeys random byte sequences each of them keylenbytes bytes long to be used as
    #keys for numkeys stages of the feistel encoder. To make sure I have control over
    #the generated random numbers meaning that the same sequence is
    #generated in different runs of the program,

    #keylist = [numkeys elements of 'bytes' type and keylenbytes bytes long each]
    keylist = []
    for i in range(numkeys):
      bytelist = b''.join([bytes([random.randint(0,255)]) for x in range(keylenbytes)])
      keylist.append(bytelist)

    return keylist


#------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------



#The main building block of the feistel cipher as a function with 3 inputs and 2 outputs
def feistel_block(LE_inp, RE_inp, k):
  #The necessary operations
  LE_out = RE_inp
  temp = F(RE_inp, k)
  RE_out = xor(LE_inp, temp)

  return LE_out, RE_out



#------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------



#The actual encoder
#This function takes in one block of plaintext, applies all rounds of the feistel
#cipher and returns the ciphertext block.

# Inputs: inputblock (byte sequence representing input block), num_rounds (integer representing number of rounds in the feistel)
# seed (integer to set the random number generator to defined state)
# Output: cipherblock (byte sequence)

def feistel_enc(inputbyteseq, num_rounds, seed):

    # Generating the required keys. 8 is the keylength in bytes
    keylist = gen_keylist(8, num_rounds, seed)

    #Next, I have to implement num_rounds of calling the block function

    # Making sure the input is 16 bytes long. If not, I add space to make it 16 bytes
    if(len(inputbyteseq) < 16):
      for i in range(0, 16-len(inputbyteseq)):
        inputbyteseq += b'\x20'

    #I split the input into two parts, a left and right equal parts
    leftInput = inputbyteseq[:len(inputbyteseq)//2]
    rightInput = inputbyteseq[len(inputbyteseq)//2:]

    #I apply one feistel block to the inputs, which returns two sequence of bytes
    feis = feistel_block(leftInput, rightInput, keylist[0])
    leftOutput = feis[0]
    rightOutput = feis[1]

    #I apply Feistel for the remaining number of rounds. The swapping is already done in
    #The feistel block code, so this will just execute.
    for i in range(1, num_rounds):
      feis = feistel_block(leftOutput, rightOutput, keylist[i])
      leftOutput = feis[0]
      rightOutput = feis[1]

    #Concatenating both outputs back into one stream of bytes
    cipherblock = rightOutput + leftOutput

    return cipherblock


#------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------



def feistel_dec(inputbyteseq, num_rounds, seed):

  keylist = gen_keylist(8, num_rounds, seed)

  #Like in the previous function, I split the inputs into two equal parts
  leftInput = inputbyteseq[:len(inputbyteseq)//2]
  rightInput = inputbyteseq[len(inputbyteseq)//2:]

  #Applying the num_rounds times of the block funciton
  feis = feistel_block(leftInput, rightInput, keylist[num_rounds-1])
  leftOutput = feis[0]
  rightOutput = feis[1]

  #range takes 3 parameters, the beginning, the end and the steps (by how many times
  #the loop will increases or decreases). I use -1 so that it goes in descending order
  for i in range(num_rounds-2, -1, -1):
    feis = feistel_block(leftOutput, rightOutput, keylist[i])
    leftOutput = feis[0]
    rightOutput = feis[1]

  #Returning back to the plaintext
  plaintextblock = rightOutput + leftOutput

  return plaintextblock


#------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------



#Main code with testing
if __name__ == "__main__":

  inp_byte = b'isthis16bytes?'
  rounds = 16
  inp_seed = 50

  encrypted = feistel_enc(inp_byte, rounds, inp_seed)
  print("FEISTEL: Input byte sequence is ", inp_byte, " and the Feistel encryption is ", encrypted)

  decrypted = feistel_dec(encrypted, rounds, inp_seed)
  print("FEISTEL: Input byte sequence is ", encrypted, " and the Feistel decryption is ", decrypted)