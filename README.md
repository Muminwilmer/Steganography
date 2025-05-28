Replaces the last bit in the image with one bit from the text which hides it in the image<br>
text = 10001001<br>
img = [01001010], [10010111]<br>
new = [01001011], [10010110]<br>
<br>
decryption just takes it back and makes it into text again<br>
<br>
you can change how many bits gets replace for each byte of image<br>
i recommend 1 or 2 but you can go up to 8 (at that point just use a text file smh)<br>
<br>
this also includes encryption and decryption<br>
<br>
The examples folder has examples on how a 1000x1000 white square would look and how many ascii letters can be hidden in it depending on the text density chosen. (Nothing is hidden in them, used the random garbage function)


TODO:

1. Optional obfuscator:
pros: impossible to know which bit is actually important even when having the original photo
cons: more obvious something has been edited in the photo.

2. support all file types as input for secret:
png, mp4, pdf etc.

3. better security overall


