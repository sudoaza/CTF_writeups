CTF EKO 2023 - Kaspersky 

We are given a pcap file and told there was an attack we need to figure out what information was stolen, and how.

Opening the pcap file in wireshark we see https traffic, some ntp traffic and one clear stream for a service apparently being exploited for a buffer overflow.
So great, there should be some shellcode in there somewhere.

![PCAP Buffer Overflow exploitation.](https://github.com/sudoaza/CTF_writeups/blob/main/img/eko23/bof_payload.png?raw=true)


We dump it to a flle and open it in Cutter. After all the "A"s we see a small nop-sled and some shellcode. This does some xor with 0x55 ("U") and 3 syscalls, memfdcreate, write and execveat.

![Assembly of the dropper.](https://github.com/sudoaza/CTF_writeups/blob/main/img/eko23/dropper_asm.png?raw=true)

After some decompiling with ChatGPT it is more clear. So we have a shellcode that creates a file in memory, writes to it and then executes it, from whenever it lands in memory, nais.

![Dropper decompiled with help of ChatGPT.](https://github.com/sudoaza/CTF_writeups/blob/main/img/eko23/dropper_pseudo.png?raw=true)

So we search for the first "U" and xor the next 0x3b50 bytes with 0x55 and save it to a file. Then we open that in Cutter again. Now it looks better.

![Unpacked, dropped binary.](https://github.com/sudoaza/CTF_writeups/blob/main/img/eko23/unpacked.png?raw=true)

After some cleanup we see it's opening some file, encrypting it with RC4 and sending it over the network. I quickly check the pcap for traffic on port 1337 but find nothing, we'll come back to that later.

![After renaming the functions the main functionality is clear.](https://github.com/sudoaza/CTF_writeups/blob/main/img/eko23/unpacked_clean.png?raw=true)

If we go to the keygen function we see it's using the current time, formating it, decoding some other string and doing some more formating. Now we do some dynamic analysis, skip the first couple of validations until we get to the keygen function, making sure all variables used as addresses are valid.

![Keygen function.](https://github.com/sudoaza/CTF_writeups/blob/main/img/eko23/genkey.png?raw=true)

Now at address 0x4040b0 lies our key, great, now we just need the ciphertext.

![Key format, we can brutforce the date or get it from the pcap.](https://github.com/sudoaza/CTF_writeups/blob/main/img/eko23/key.png?raw=true)

And this is as far as I got during the CTF, I tried decrypting the binary itself at all offsets, xored with 0x33 and 0x55 but no luck. It was until after the CTF, reading [avpxyyf writeup](https://avpxyyf-sec.blogspot.com/2023/11/kaspersky-writeup-ekoparty2023.html) that I learned that the TCP port was 0x1337 and NOT 1337, a valuable lesson that I will not forget.


In the end this would have been a good amount of points but not enought to get us to the first place.

![D](https://github.com/sudoaza/CTF_writeups/blob/main/img/eko23/eko23.png?raw=true)