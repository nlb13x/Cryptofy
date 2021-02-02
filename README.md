# Cryptofy
Python script for encrypting and decrypting messsages

- Create a message.txt containing your message
- To create a text file, containing your encrypted message, run the command<br>
`python3 crypto.py -e crypto.py < message.txt > cipher.txt`<br>
and enter the password you wish to use
- You will be able to view your encryted message in cipher.txt
- Now, to decrypt your message, run the following command <br>
`python3 crypto.py -d crypto.py < cipher.txt > encrypted.txt`<br>
and enter the password you used to decrypt the message
- Your original message will be stored in `encrypted.txt`
