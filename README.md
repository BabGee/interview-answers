# interview-answers


## Section A

### Q1. Examples of intergration protocols with Python3 scripts and how to achieve them.*

* API(Application Programming Interface)
    - APIs enable interaction between applications.
    - API uses Common code language to specify functionality and set protocols giving applications the ability to transfer data.

* Webhooks
    - Webhooks are user-defined HTTP callbacks that allow interactions between otherwise independent we applications.
    - Webhooks are event-based and only trigger when specific events occur within a third party service.

#### API intergration in python3
Python uses a HTTP library called `requests` which doesn't come with the standard library. To install:

```bash
python -m pip install requests
```

Lets create a to-do list API with the following Methods:

* GET /tasks/
Returns a list of items in the to-do list in the following json format:

```bash
{
    "id": "<item_id>", 
    "description": "<one-line description>"
}
```
example script

```bash
import requests

resp = requests.get('https://todolist.example.com/tasks/')
if resp.status_code != 200:
    # This means something went wrong.
    raise ApiError(f'GET /tasks/ {resp.status_code}')
for todo_item in resp.json():
    print(todo_item['id'], todo_item['description'])
```

* GET /tasks/<item_id>/
Returns all information for a specific to-do item in json format:

```bash
{
    "id": "<item_id>", 
    "description": "<one-line description>"
}
```
example script

```bash
import requests

resp = requests.get('https://todolist.example.com/tasks/1')
if resp.status_code != 200:
    # This means something went wrong.
    raise ApiError(f'GET /tasks/id {resp.status_code}')
todo_item = resp.json()
print(todo_item['id'], todo_item['description'])
```

*  POST /tasks/
Creates a new to-do item.
POST body is a JSON object with 1 field: `description`
On success, the status code is 201 and the response body is an object with one field: the id created  by the server. For Example  

```bash
{
    "id": 420, 
}
```
example script

```bash
import requests

task = {
    "decription" : "Learn django deployment"
}

resp = requests.post('https://todolist.example.com/tasks/', json=task)
if resp.status_code != 201:
    raise ApiError(f'POST /tasks/ {resp.status_code}')
print(f'Created task ID: {resp.json()['id']}')
```

DELETE /tasks/<item_id>/
This method deletes the specified to-do item from the to-do list.
The response body is empty.

PUT /tasks/<item_id>/
This method modifies an existing to-do item.
PUT body is a JSON object with 1 field: `description`


#### Receiving a webhook with Django

Use pip to install Django 

```bash
    python -m pip install Django
```

If setting up a project from scratch use the `django-admin` utility to create new project

```bash
django-admin startproject example-project
```
set up an app called webhooks

```bash
python manage.py startapp webhooks
```

##### * webhooks/views.py
The logic for handling a route.

```bash
from django.http import HttpResponse
from django.views.decorators.http import require_POST

@require_POST
def example(request):
    return HTtpResponse('Hello There! This is a webhook response')
```

##### * webhooks/urls.py
we create webhook.urls.py file to organize routes within our sub-app.

```bash
from django.urls import path
from . import views

urlpatterns = [
    path('example/', views.example)
]
```
In this instance, we define a path that targets `example/` and is associated with the view `views.example` which was the name of our function in `views.py`


##### * example-project/urls.py
To make sure that the outer project knows about our app we add a new path as below:

```bash
urlpatterns = [
    ... ,
    path('webhooks/', include('webhooks.urls'))
]
```
Run server `python manage.py runserver` and make a POST request to `http://127.0.0.1:8000/webhooks/example/`

With that, we have set up a Django project that listens for a webhook at `/webhooks/example/`

*
### Q2. Walkthrough on how to manage a data streaming application sending one million notifications every hour with example technologies and configurations used to manage load and asynchronous services.

#### Using asyncio
`asyncio` is a Python library that allows you to execute some tasks in a seemingly concurrent manner.
It is also useful for speeding up IO-bound tasks, like services that require making many requests or do lots of waiting for external APIs.


### Q3. Encryption/ Hashing methods with example scripts in python3 on how to achieve each one
Implementing Hash functions: SHA1, SHA3, and BLAKE2, Message Authentic Code: HMAC and functions that generate secret keys from passwords-Key Derivation Functions: Scrypt and Argon2 in Python.

#### Implementation of Hash functions  SHA1, SHA3 and BLAKE2
The Python module `hashlib` provides a simple to use interface for the hash function in cryptography.

#### SHA3
#### Example script for `sha3–512` hash function from the SHA3 family.

```bash
    import hashlib
    from binascii import hexlify

    data = 'Elon Musk is a masked alien'
    data = data.encode('utf-8')
    sha3_512 = hashlib.sha3_512(data)
    sha3_512_digest = sha3_512.digest()
    sha3_512_hex_digest = sha3_512.hexdigest()

    print('Printing digest output')
    print(sha3_512_digest)

    print('Printing hexadecimal output')
    print(sha3_512_hex_digest)

    print('Printing binary hexadecimal output')
    print(hexlify(sha3_512_digest))

    Output:

    Printing digest output
    b'\x01c*\x93\x8a\xceZ^\xa2Y\xd8\x9b\xe7\xdb\n\xe6\x91\xb3G\x9b\x90\xf0\xday\xdb\x88\xe3\x96\x9bE\xa3\xc5U\xa9\xda\x05\xd9\xf1\xa6\x07\xd0\x9b\x13$3I\x0e\xd8uz\xa8\x14lak\x0b|\xa6\xa0GS\xaf\x87\x97'
    
    Printing hexadecimal output
    01632a938ace5a5ea259d89be7db0ae691b3479b90f0da79db88e3969b45a3c555a9da05d9f1a607d09b132433490ed8757aa8146c616b0b7ca6a04753af8797

    Printing binary hexadecimal output
    b'01632a938ace5a5ea259d89be7db0ae691b3479b90f0da79db88e3969b45a3c555a9da05d9f1a607d09b132433490ed8757aa8146c616b0b7ca6a04753af8797'
```

We import `hashlib` and `binascii`. `hashlib` contains the hash functions and `binascii` is a module for binary-to-ascii and ascii-to-binary conversions.

Since the hash functions in Python take the data in bytes we encode it into bytes using the `encode()` function of the `String` class and it takes the default argument `utf-8` which encodes it into 8-bit Unicode format.

Next, we instantiate a `sha3_512` class from the `hashlib` module and it takes in one argument— the data to be hashed in bytes

We get the output, called the `digest`, of the hash function, by applying the `digest()` method on the hash object

The result is in bytes. If we want the digest in hexadecimal we use the `hexdigest()` method.

The output of `hexdigest` is a string type. If we want `hexdigest` in bytes we apply a method called `hexlify` of `binascii` module to convert the digest output into hexadecimal bytes.

#### SHA1
#### Example script for `sha256` hash function from the SHA1 family.

```bash
    from hashlib import sha256

    sha256_digest = sha256(b'Elon Musk is a masked alien')

    digest = sha256_digest.digest()
    print('Printing digest output')
    print(digest)

    hexdigest = sha256_digest.hexdigest()
    print('Printing hexadecimal output')
    print(hexdigest)


    Output:

    Printing digest output
    b'\xdc\xd5\xf6\xf6h\xe42</.\xd72\xa3\xfaE\x99\xee\xfe\x86a\x124\xa0\x81q\xb5)ms\x12p('
    
    Printing hexadecimal output
    dcd5f6f668e4323c2f2ed732a3fa4599eefe86611234a08171b5296d73127028

```

We instantiated a sha256 object and added the data and computed both the digest and hexdigest

NOTE: SHA1 family hash functions have many vulnerabilities and therefore not advised to be used.

#### BLAKE2
BLAKE2 is a cryptographic hash function defined in RFC 7693 that comes in two flavors:
1. `blake2b`
2. `blake2s`
##### Example script for `blake2b` hash function from the BLAKE2 family.

`blake2b` is optimized for 64-bit operating systems and outputs varying length hash functions up to 64 bytes.

```bash
    from hashlib import blake2b

    data = b'Elon Musk is a masked alien'
    blake = blake2b(data, digest_size=32)

    print('Printing blake digest')
    print(blake.digest())

    print('Printing blake hexadecimal digest')
    print(blake.hexdigest())

    Output:
    Printing blake digest
    b'\xf7 \xb0FU6\x0eI\n\xaf\xa6"\x175<1u\xb6\x17 P\x93\xa8\xcf\x05\x16w7\xe6\x84\x00\x1f'

    Printing blake hexadecimal digest
    f720b04655360e490aafa62217353c3175b617205093a8cf05167737e684001f

```
##### Example script for `blake2s` hash function from the BLAKE2 family.

`blake2s` is optimised for 8- to 32-bit platforms and outputs varying length hash functions up to 32 bytes.

```bash
    from hashlib import blake2s

    data = b'Elon Musk is a masked alien'
    blake = blake2s(data, digest_size=32)

    print('Printing blake digest')
    print(blake.digest())

    print('Printing blake hexadecimal digest')
    print(blake.hexdigest())

    Output:
    Printing blake digest
    b'\x1c\xec\xf0\xd7\x94\xdcq\xdf/\xf2\x87D\x87\xb5Pu\xbe\xee\xc8\x89\xa3\x98\x195\xfb\x89\x8a\x82++\x0c\xe7'

    Printing blake hexadecimal digest
    1cecf0d794dc71df2ff2874487b55075beeec889a3981935fb898a822b2b0ce7

```
#### Implementation of Message Authentication Codes
Message Authentication Code (MAC) behaves like a hash function with a key.
It is also known as keyed hash functions. Some of MACs are HMAC (Hash-based MAC), CMAC (Cipher-based MAC), Poly1305. 

##### Implementation of Hashed Message Authentication Code (HMAC)
```bash
    import hmac, hashlib

    data = b'Elon is from Mars'
    key = b'keyed-version'

    hmac_code = hmac.new(key=key, msg=data, digestmod=hashlib.sha3_256)
    hmac_digest = hmac_code.digest()
    hmac_hexdigest = hmac_code.hexdigest()

    print('HMAC digest: ', hmac_digest)
    print('HMAC hexdigest: ', hmac_hexdigest)

    Output:

    HMAC digest: b"; \xe7\xfb\x84\xcb{\x9c\xe4n\x89\xc8\x18M\xf5Y\xfa\xca\xcd\xdb\xc2\xc0\xf0f+\xf0'\x1cU\x86!\xb2"

    HMAC hexdigest:  3b20e7fb84cb7b9ce46e89c8184df559facacddbc2c0f0662bf0271c558621b2

```
We imported the `hmac` and `hashlib` modules and declared our data and the key that we intend to use. The `new` constructor takes in three arguments, `key`, `msg` — the data and `digestmod` — the particular hash function we use. Both the ‘key’ & ‘msg’ arguments should be bytes or byte array objects. We use the sha3_256 hash function.Then finally we compute both the digest and hexdigest.

##### Implementation of Poly1305
It is a faster MAC calculating algorithm that requires a 32-byte secret key, nonce ( a random value ), a symmetric cipher (AES or ChaCha20).
We need to install the `pycryptodome` package.

```bash
 python3 -m pip install pycryptodome
```


```bash
    from Crypto.Hash import Poly1305
    from Crypto.Cipher import AES

    key = b'The key size has to be 32 bytes!'
    mac = Poly1305.new(key=key, cipher=AES)

    mac.update(b'message to be delivered')
    mac_nonce = mac.nonce
    mac_hex_digest = mac.hexdigest()

    print('Poly1305 nonce: ', mac_nonce)
    print('Poly1305 hex_digest: ', mac_hex_digest)

    mac_verify = Poly1305.new(key=key, nonce=mac_nonce, cipher=AES, data=b'message to be delivered')

    try:
        mac_verify.hexverify(mac_hex_digest)
        print('The message is authentic')

    except:
        print('The message cannot be authenticated')

    Output:
     
    Poly1305 nonce: b'\x11E\xd9\x8d\x19x\xf6\x03\xd4\xd8V\x08q\xa8M\xc4'

    Poly1305 hex_digest: 2f945d953d2eb631881da15f201f1dc9
    
    The message is authentic

```
The Poly1305 resides in the `Crypt.Hash` module and we are taking the AES cipher from Crypto.Cipher to use with Poly1305. We can also use ChaCha20 cipher.
After importing the necessary libraries, we initialize the key which has to be 32 bytes long.
We then create an object of the `new` class of Poly1305 with three arguments, the `key`, the kind of `cipher` and `nonce`.

`nonce` is a random value initializable value, 16-bytes in the case of AES and 8 or 12 in the case of ChaCha20. Failure to specify `nonce` value then it itself initializes some random value. But to verify we need to keep the `nonce` later to verify the `MAC` to be used in another Poly1305 object. We can get the `nonce` variable with the `Poly1305.new().nonce` attribute.

We get the hexdigest of the MAC by using the `hexdigest()` method on the Poly1305 object.

Let’s say a sender has sent the message along with the MAC, nonce (here it is symmetric cryptography, so the receiver should also have the same key) and the receiver generates a new MAC from the received message and compares with the received MAC to make sure that the message has not been altered or tampered with.

If we want to verify the received MAC with the MAC generated from the received message, we have to create a new object of Poly1305 with the key and nonce (the same nonce used by the sender to generate the MAC) values received along with the MAC.

If the message is the same then we can verify that the message has not been altered or tampered with during the transmission.

#### Key Derivation Functions(KDFs)
KDFs are the function to securely derive keys from passwords.
These functions derive secure keys from passwords which aren’t easily interpretable.
KDFs are are highly resilient to brute force attack, rainbow attack, and dictionary attack by the usage of `salt` (random number) and `iteration` (number of iterations to produce the final key) and many other arguments.
Some of the KDFs are Scrypt, Bycrypt, Argon2

##### Implementation of Scrypt
We need to install the Scrypt library using `pip`

```bash
    python3 -m pip install Scrypt
```

Scrypt takes the following parameters:
1. N — iterations count, usually 16384 or 2048.
2. r — block size, eg. 8.
3. p — parallelism factor (threads to run in parallel), usually 1.
4. password — the input password
5. salt — securely generated random bytes
6. buflen — the length of the output key in bytes.

```bash
    import scrypt, secrets

    password = b'not a number'
    salt = secrets.token_bytes(32)
    scrypt_key = scrypt.hash(password, salt, N=16384, r=8, p=1, buflen=32)

    print('Salt: ', salt)
    print('Key: ', scrypt_key)

    Output:

    Salt: b'\xcft@\x80\xae)\x0b\xf4\xbb\x85S\x02\xd5Q\xaa\x10\xdbG\x12\x12\x89\x99\xc6]\xb7\xb3\xd7CeR\x15h'

    Key: b'\x8c,{\xe8*\xce\x12\xa7\x8aU\x89\x8fF?\x13\xd4a \x05\r`"\x87J\xc9\x12E\x8a\x18\xc7\x94a'

```
The `scrypt.hash()` method returns the key in bytes. To generate we used the `token_bytes` function from the `secrets` module, which takes a byte size argument in.


##### Implementation of Argon2
We need to install the `argon2-cffi` module using `pip`

```bash
    python3 -m pip install argon2-cffi
```

There are 3 variants for Argon2:
1. Argon2d — Provides strong GPU attacks, but has potential side-channel attacks.
2. Argon2i — Provides less resistance to GPU attacks, but has no side-channel attacks.
3. Argon2id — Combination of both Argon2i and Argon2d, highly recommended and the default one.

The `PasswordHasher` class is used for deriving the keys from the passwords.

Argon2 `PasswordHasher` class takes the following parameters:
1.time_cost — the number of iterations.
2 memory_cost — defines the memory usage, given in kibibytes.
3. parallelism — the number of parallel threads.
4. hash_len — the length of the hash in bytes.
5. salt_len — the length of the random salt to be generated for each password.
6. encoding — the type of encoding for the arguments passed to the methods, the default is `utf-8`.
7. type — the variants to Argon2 to be used, Argon2id is the default. Represented by `Type.<x>`, where `x` can be `I` for Argon2i, `D` for Argon2d or `ID` for Argon2id. `Type` is an enum class of Argon2.

```bash
    import argon2

    password = b'not a number'
    argon = argon2.PasswordHasher(time_cost=2000, memory_cost=102400,
                parallelism=8, hash_len=16,encoding='utf-8',
                type=argon2.Type.D)
    key = argon.hash(password='not a number')
    print(key)

    Output:
    $argon2d$v=19$m=102400,t=2000,p=8$ZMSRcZgTDGSRVwN7h9QtrQ$4Mo24LQveN0rLxKliPrdGg
```
We instantiate an argon2 object then get the key by applying the method `argon.hash` with an argument `password` which can be either a byte or Unicode string. The output format stores the config parameters along with the key. The key is the string following the last `$` sign.


#### AES ecryption in python
Install the `pycryptodome` package.

```bash
 python -m pip install pycryptodome
```

```bash
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Cipher import AES

    BLOCK_SIZE = 32 # Bytes

    key = 'abcdefghijklmnop'
    cipher = AES.new(key.encode('utf8'), AES.MODE_ECB)
    msg = cipher.encrypt(pad(b'hello', BLOCK_SIZE))

    print(msg.hex()) # e3d29336a264daeee75140d0a8db01ead491288ab573997212b96ff440119c0d

    decipher = AES.new(key.encode('utf8'), AES.MODE_ECB)
    msg_dec = decipher.decrypt(msg)

    print(unpad(msg_dec, BLOCK_SIZE)) # b'hello'
```

#### DES ecryption in python
Install the `pycryptodome` package.

```bash
 python -m pip install pycryptodome
```

```bash
    from Crypto.Cipher import DES

    def pad(text):
        n = len(text) % 8
        return text + (b' ' * n)


    key = b'hello123'
    text1 = b'Python is the Best Language!'

    des = DES.new(key, DES.MODE_ECB)

    padded_text = pad(text1)
    encrypted_text = des.encrypt(padded_text)

    print(encrypted_text.hex()) # 7b015efed5d18f4d1accd5bc041c0e6d242cc1c7772d4831e63e082521abd058
    print(des.decrypt(encrypted_text)) # b'Python is the Best Language!    '
```

## Section B
### Q5. Search and results page using Django and postgreSQL database.

Created a Django project (interintel) and app (search)

Created the logic in search/views.py for handling the search_results

Created a Dockerfile inside the project using base python image alpine version copied all the necessary folders and files and downloaded the dependencies and requirements.txt.

Created a Nginx folder and created a Dockerfile specifically for nginx together with its configuration file

Created the docker-compose.yml with services: web, db(postgres) and nginx

Before running the container make sure you set your postgres configurations appropriately for the environment:
```bash

    environment:
        - POSTGRES_USER=postgres
        - POSTGRES_PASSWORD=password
        - POSTGRES_DB=search_db
        
```
I used django-seed to generate dummy data to populate the database

To search for a product click on the all products link on the homepage to view all products to get to know what to search for 
