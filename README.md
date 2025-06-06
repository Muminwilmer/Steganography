Replaces the LSB (Last bit of every byte) with 1 bit of text, Each (ascii) letter needs 8 pixels to be hidden.<br>
Secret = [(1)0001001]<br>
Source = [0100101(0)]
Image = [0100101(1)]

Secret = [1(0)001001]<br>
Source = [1001001(1)]<br>
Image = [1001001(0)]<br>

<br>
decryption just takes it back and makes it into text again<br>
Has 2 modes, Paranoia and Normal:
Paranoia Lets you have two passwords, One for encrypting the text and one for the LSBs order
Normal uses only 1 password, Encryping is one and LSB uses the encrypted password as the order
(No password is possible but shows multiple warnings, uses standard left-to-right lsb)


<br>


TODO:

1. Optional obfuscator:
pros: impossible to know which bit is actually important even when having the original photo
cons: more obvious something has been edited in the photo.

(Done!) 2. support all file types as input for secret:
png, mp4, pdf etc.

3. better security overall (future-proof for quantum computers)

(Done!) 4. Use bits for everything to better support non ascii characters, only convert to ascii after decryption.

5. Move code used at multiple places into better functions.

6. more readability, add functions to add an read LSBs instead of weird math.

