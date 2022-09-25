Flaskmetal Alchemist was a web medium challenge in which we were given the source code for a Python application based on the Flask framework and the SQLAlchemy ORM library. As the name was suggesting this application has a SQL injection vulnerability and some quick testing showed the order clause to be injectable.

Since our injection is in the order clause we cannot select data directly but can do a subquery to affect the order, or even better, the limit.

While reading other writeups about the challenges I was surprised to find that in every case ( [iwanflagz](https://iwanflagz.github.io/nahamcon-2022-writeups/web/fma.html), [ghostccamm](https://ghostccamm.com/writeups/nahamcon-2022),  [DauHoangTai](https://gist.github.com/DauHoangTai/f6ace49fa6d6cbf4ed0e0c0dcc4ab334#file-flaskmetal-alchemist-py) ) they had taken a blind binary search exfiltration approach, and since I did it differently, I wanted to share my way.

Since we are told in the challenge description that:

> NOTE: this flag does not follow the usual MD5 hash style format, but instead is a short style with lower case flag\{letters\_with\_underscores\}

And we have around 100 results to the search I figured it would be faster to get directly the ASCII code of each letter by using it in the limit clause, one request per character, instead of the 8 request per character for binary search (or more if you simply bruteforce the character). Since the largest code we are expected to get is 125 for `}` I subtracted 40 to it and used it in the limit like so:

```sql
atomic_number limit (SELECT unicode(substr(flag, 1, 1)) - 40 FROM flag)
```

After getting the results we simply count the items, add 40 and convert back to ASCII.

And we get flag\{order\_by\_blind\} although we peeked a bit.