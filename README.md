# simplejwt
Simple implementation for reading, creating, signing and verifying JWTs

## Usage

```json
import { JWT } from '@muisit/simplejwt'

const jwt = JWT.fromToken(token);
const { kid, iss } = jwt.header;
const { aud, nbf, iat } = jwt.payload;
const ckey = jwt.findKey();
if (ckey) {
    if (!jwt.verify(ckey)) {
        console.log('JWT could not be verified');
    }
}

const mysigningkey = await Factory.createKeyFromType('Ed25519', "private key in hex");
jwt.sign(mysigningkey);
console.log('JWT token is ', jwt.token);
```
