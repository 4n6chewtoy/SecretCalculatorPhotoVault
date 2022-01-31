####
# A python script designed to decrypt media files encrypted using the Android application
# 'Secret Calculator Photo Vault'. Script also supports bruteforce of unknown PIN
# Original blog post: https://theincidentalchewtoy.wordpress.com/2022/01/27/decrypting-secret-calculator-photo-vault/
###

# Import required modules
import sys
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Cipher import AES 
import binascii
import os
import base64
import xml.etree.ElementTree as ET
import filetype 
import hashlib

print('------------------------------------------------------------------------------')

# Take the user PIN. Either specify it or press enter to bruteforce.(Limited user input validation.) 
while True:
    userPIN  = input('Enter PIN (if not known press enter):')
    if not userPIN:
        print("\n****PIN not provided, will bruteforce****\n")
        userPIN = None 
        break
    ## Check user input are digits
    try:
        int(userPIN)
    except ValueError:
        print('Input is not an intiger')
        continue
    ## Check the length of the entered PIN is between 4 and 8    
    if len(str(userPIN)) > 8 or len(str(userPIN)) < 4:
        print('PIN needs to be between 4 & 8')
        continue
    else:
        ## Print the provided PIN 
        print(f'\nUser PIN provided:\t\t\t\t{userPIN}\n')
        break
        
#/data/data/ folder as input
cwd = sys.argv[1]

## /sdcard/ inpu
media_dir = ""

## Specify output folder
output_dir = sys.argv[2]

### Check for shared_preferences subfolder
if('shared_prefs' in next(os.walk(cwd))[1]):
    ### If shared_preferences folder exisits, check for the file 'AppPreferences.xml'
    if(os.path.join(cwd, 'shared_prefs\AppPreferences.xml')):
        shared_prefs = (os.path.join(cwd, 'shared_prefs\AppPreferences.xml'))
        ### If the file exisits, read the contents of <string name="pbkdf2_salt"> 
        tree = ET.parse(shared_prefs)
        root = tree.getroot()
        ### Retrieve the pbkdf2 salt
        masterSalt = base64.b64decode(root.findall('./string[@name="pbkdf2_salt"]')[0].text)
        ### Retrieve the symmetric key
        symmetricKey = base64.b64decode(root.findall('./string[@name="symmetric_encrypted_files_encryption_key"]')[0].text)
        ### Retrieve the hash
        hashedEncryptionKey = base64.b64decode(root.findall('./string[@name="hashed_files_encryption_key"]')[0].text)
        ### Print the salt
        print(f'The salt for the Primary Key is:\t\t{masterSalt.hex()}')
        print(f'The Hashed Encryption Key is:\t\t\t{hashedEncryptionKey.hex()}')

### Check for encrypted files subfolder
if('files' in next(os.walk(cwd))[1]): 
    if(os.path.join(cwd, 'files\calculator_encrypted_DoNotDelete')):
        media_dir = shared_prefs = (os.path.join(cwd, 'files\calculator_encrypted_DoNotDelete'))
    else:
        print("Could not find encrypted files folder, exiting")
        exit

def identifyKey(PIN):
    ## Derive the Primary key from the provided PIN
    masterKey = PBKDF2(PIN, masterSalt, 32, count=4096, hmac_hash_module=SHA256)
    ### Decrypt the Symmetric Key which will give the overall master key for the media file decryption.
    cipher = AES.new(bytes.fromhex(masterKey.hex()), AES.MODE_GCM, bytes.fromhex(mediaIV))
    masterMediaEncryptionKey = cipher.decrypt(bytes.fromhex(mediaEncryptionKey))
    return(masterMediaEncryptionKey,masterKey)

### This section will check whether a PIN was already provided. If it was provided then it will skip bruteforce. 
## If userPIN is none, it means one wasn't specified and it needs to be bruteforced.
mediaIV = symmetricKey.hex()[4:28]
mediaEncryptionKey = symmetricKey.hex()[28:92]

if userPIN is None:
    ## For each passcode it will need to run the cryptographic function and compare the hashed result to the 
    ## hashed_files_encryption_key. If it is wrong it will keep trying
    for i in range(0,100000000):
        currentPIN = ('{0:04}'.format(i))
        ## Section of code to try the crypto process and assign PasscodFound if correct
        encKeys = identifyKey(currentPIN)
        ## Compare the current PIN PBKDF2 and the hashedEncryptionKey
        if hashlib.sha256(encKeys[0]).hexdigest() == hashedEncryptionKey.hex():
            print(f'FOUND PIN:\t\t\t\t\t****{currentPIN}****')
            pinFound = True
            break
        else:
            continue        
    ## If the PIN is not found then exit
    if not pinFound:
        print('****PIN not found, program will exit***')
        exit()
## If the user pin was already provided just do the decryption
else:        
    encKeys = identifyKey(userPIN)

## Print results to user
print(f'Primary Key (from PIN):\t\t\t\t{encKeys[1].hex()}')
print(f'The IV for the master Key is:\t\t\t{mediaIV}')
print(f'The Encrypted Master Key:\t\t\t{mediaEncryptionKey}')
print(f'The Decrypted Master Key\t\t\t{encKeys[0].hex()}')
print('------------------------------------------------------------------------------')

#### DECRYPTING THE FILES ####
### Check to see if the database is present
for dirpath, dirnames, filenames in os.walk(media_dir):
    ### For each folder in the media directory
    for directories in dirnames:
        print(f'Found folder:\t\t\t\'{directories}\'\n')
        print('------------------------------------')
        print(f'Checking for files in \'{directories}\'')
        print('------------------------------------')
        ### Check if there are any files in the folder
        if not(os.listdir(os.path.join(dirpath,directories))):
            print('Folder contains no files\n')
            print('------------------------------------')
        else:
            print('Found files...will attempt to decrypt')
            print('Creating output folder for decrypted files')
            ### If the folder doesn't exist, create it.
            if not os.path.exists(os.path.join(output_dir,directories)):
                os.makedirs(os.path.join(output_dir,directories))
                print('Created external directory')
            else:
                print('Directory already exists, skipping creation')
            ### For each file in the directory
            for files in (os.listdir(os.path.join(dirpath,directories))):
                
                print(f'Found file:\t\t\t{files}')
                print(f'Attempting to decrypt:\t\t{files}')
                ### Open file to be decrypted
                with open ((os.path.join(dirpath,directories,files)), 'rb') as currentFile:
                    encryptedData = currentFile.read()
                    currentIV = (encryptedData[2:14])
                    ### Encryption algo
                    cipher = AES.new(bytes.fromhex(encKeys[0].hex()), AES.MODE_GCM, bytes.fromhex(currentIV.hex()))
                    ### Decrypt the data
                    decryptedData = cipher.decrypt(encryptedData[14:])
                    ### Determine the correct file extension
                    fileExtension = filetype.guess(decryptedData)
                    ### Open file for writing
                    with open ((os.path.join(output_dir,directories,files[:-4] + f'.{fileExtension.extension}')) , 'wb') as decryptedFile:
                        decryptedFile.write(decryptedData)
                        decryptedFile.close()
                        print(f'File Decrypted Successfully')  
                        print('------------------------------------')