import { KeyPair, ec } from 'elliptic';
import { Arrayish, arrayify } from './bytes';

const ed25519 = ec('ed25519');

export class SigningKey {
  keyPair: KeyPair;

  constructor(privateKey: string) {
    this.keyPair = ed25519.keyFromPrivate(privateKey, 'hex');
  }

  signDigest(digest: Arrayish) {
    const signature = this.keyPair.sign(arrayify(digest), { canonical: true });

    const result = {
      recoveryParam: signature.recoveryParam,
      r: signature.r.toString('hex'),
      s: signature.s.toString('hex'),
      v: 27 + signature.recoveryParam,
    };

    return result;
  }
}
