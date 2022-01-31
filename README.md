# SecretCalculatorPhotoVault
A python script to decrypt media files encrypted using the Android application 'Secret Calculator Photo Vault'. Supports brute force of PIN also.
Original Blog Post: https://theincidentalchewtoy.wordpress.com/2022/01/27/decrypting-secret-calculator-photo-vault/

‘Secret Calculator Photo Vault: Hide Keep Safe Lock’ uses ‘Military Grade Encryption AES-256 bit‘ to keep files safe within the application. The developers also make the following statement: ‘Secret Calculator’s architecture was developed with the help of data security consultants experts to make sure that nobody, including our team, will be able to access your private photo locker without knowing your pass phrase, even if your device is stolen!'

## Script Usage

Script takes 3 aguments:

1. PIN
2. Input folder (/data/data/com.photovault.secret.calculator)
3. Output folder

The script will ask the user for the PIN, there is limited validation of the input. If the user chooses not to enter a PIN then the script will attampt to bruteforce it.

If a correct PIN is given or bruteforce is achieved then the script will move on to decrypting and outputting the media files.

Any questions, or issues let me know https://twitter.com/4n6chewtoy
