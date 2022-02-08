# pyRansom
## Author: [Raphael Dray](https://www.linkedin.com/in/raphaeldray/)
pyRansom is not a ransomware but a tool designed to encrypt/decrypt 
using either symmetrically either asymmetrically a given file and checking
its integrity using either [HMAC-SHA-256](https://fr.wikipedia.org/wiki/HMAC) 
either [RSA-PSS signature](https://en.wikipedia.org/wiki/Probabilistic_signature_scheme).

It can be used, for now, to encrypt/decrypt symmetrically using 
[AES](https://fr.wikipedia.org/wiki/Advanced_Encryption_Standard)
-256-[CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC))
with a given password that will be used to generate round keys.

Also, it can be used to encrypt/decrypt asymmetrically using 
[RSA-OAEP](https://fr.wikipedia.org/wiki/Optimal_Asymmetric_Encryption_Padding) 2048
to encrypt only the CipherKey (used by the AES to encrypt data)
in case of single user sending and to encrypt the CipherKey plus 
the 
[Initialization Vector](https://en.wikipedia.org/wiki/Initialization_vector#:~:text=In%20cryptography%2C%20an%20initialization%20vector,to%20be%20unpredictable%20or%20unique.) 
(used by the AES to encrypt data) in case
of multi-protect sending.

---
### Installation:
You'll need [Python 3.8+](https://www.python.org/downloads/) to run this script.
* Clone this repository:
    ```shell
    git clone git@github.com:MrrRaph/pyRansom.git
    ```
* Install the requirements:
    ```shell
    pip install -r requirements.txt
    ```

---
### Usage:
#### General Options:
```
usage: pyRansom.py [-h] --input <Input Filename> --output <Output Filename> (--encrypt | --decrypt) {sym,asym} ...

Encrypt/Decrypt given file

positional arguments:
  {sym,asym}            Encryption Mode
    sym                 Symmetric Mode
    asym                Asymmetric Mode

optional arguments:
  -h, --help            show this help message and exit

I/O:
  --input <Input Filename>, -i <Input Filename>
                        Input file to Encrypt/Decrypt
  --output <Output Filename>, -o <Output Filename>
                        Output file to save the encrypted/decrypted

Cipher Mode:
  --encrypt, -e         Encrypt mode
  --decrypt, -d         Decrypt mode
```
---
#### Symmetric Encryption:
```
usage: pyRansom.py sym [-h] --password <Password>

optional arguments:
  -h, --help            show this help message and exit

Symmetric Encryption:
  --password <Password>, -p <Password>
                        Password to be used to encrypt/decrypt the file
```

**Example:**
Start by encrypting your Input File using your password (e.g. myP@$$W0rd)
```shell
python pyRansom.py -e --input venv\Scripts\activate.fish --output output\activate.fish.enc sym -p myP@$$W0rd
```

Then you can decrypt your Output File as follows:
```shell
python pyRansom.py -d --input output\activate.fish.enc --output output\activate.fish.dec sym -p myP@$$W0rd
```
---
#### Asymmetric Encryption:
```
usage: pyRansom.py asym [-h] --private-key <Private Key Filename> --public-key <Public Key Filename> [<User Public Key> [<User Public Key> ...]]

optional arguments:
  -h, --help            show this help message and exit

Asymmetric Encryption:
  --private-key <Private Key Filename>, -priv <Private Key Filename>
                        Receiver/Sender Private Key
  --public-key <Public Key Filename>, -pub <Public Key Filename>
                        Receiver/Sender Public Key
  <User Public Key>     User Public Key (Multi-Protected File)
```

##### Single Sending:
For encryption, you have to use the sender private key and the receiver public key.
```shell
python pyRansom.py -e --input venv\Scripts\activate.fish --output output\activate.fish.enc asym -priv senderPriv.pem -pub receiverPub.pem
```

For decryption, you have to use the receiver private key and the sender public key.
```shell
python pyRansom.py -d --input output\activate.fish.enc --output output\activate.fish.dec asym -priv receiverPriv.pem -pub senderPub.pem
```

---
##### Multi-Protect Sending:
For encryption, you have to use the sender private key and the sender public key.
Then you can specify all the receivers public keys, only those could decrypt the file.
```shell
python pyRansom.py -e --input venv\Scripts\activate.fish --output output\activate.fish.enc asym -priv senderPriv.pem -pub senderPub.pem users\Thierry\thierry-pub.pem users\Lorens\lorens-pub.pem
```

For decryption, for example, Thierry as the receiver, will use its own private key, 
the sender public key and specify its public key.
```shell
python pyRansom.py -d --input output\activate.fish.enc --output output\activate.fish.dec asym -priv users\Thierry\thierry-priv.pem -pub senderPub.pem users\Thierry\thierry-pub.pem
```