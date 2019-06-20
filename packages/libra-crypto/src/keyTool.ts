import elliptic from 'elliptic';

import { sha3_256 } from './keccak256';
import { randomBytes } from './random';

// import { encode } from './rlp';

export const ec = elliptic.ec('curve25519');

/**
 * @function generatePrivateKey
 * @description generatePrivate key using `eth-lib` settings
 * @return {string}
 */
export const generatePrivateKey = (): string => {
  return randomBytes(32);
};

/**
 * @function getPubkeyFromPrivateKey
 * @param  {string} privateKey - private key String
 * @return {string}
 */
export const getPubkeyFromPrivateKey = (privateKey: string): string => {
  return getPublic(privateKey);
};

/**
 * @function getAddressFromPrivateKey
 * @param  {string} privateKey - private key string
 * @return {string} address with `length = 40`
 */
export const getAddressFromPrivateKey = (privateKey: string): string => {
  const address = sha3_256('0x' + getPublic(privateKey));
  return address;
};

export const getPublic = (privateKey: string): string => {
  const ecKey = ec.keyFromPrivate(privateKey, 'hex');
  return ecKey.getPublic(false, 'hex');
};

/**
 * @function getAddressFromPublicKey
 * @param  {string} publicKey - public key string
 * @return {string} address with `length = 40`
 */
export const getAddressFromPublicKey = (publicKey: string): string => {
  const address = sha3_256('0x' + publicKey);
  return address;
};

// /**
//  * @function toChecksumAddress
//  * @param  {string} address - raw address
//  * @return {string} checksumed address
//  */
// export const toChecksumAddress = (address: string): string => {
//   if (typeof address !== 'string' || !address.match(/^0x[0-9A-Fa-f]{40}$/)) {
//     errors.throwError('invalid address', errors.INVALID_ARGUMENT, {
//       arg: 'address',
//       value: address,
//     });
//   }

//   address = address.toLowerCase();

//   const chars = address.substring(2).split('');

//   let hashed = new Uint8Array(40);
//   for (let i = 0; i < 40; i++) {
//     hashed[i] = chars[i].charCodeAt(0);
//   }
//   hashed = bytes.arrayify(keccak256(hashed)) || hashed;

//   for (let i = 0; i < 40; i += 2) {
//     if (hashed[i >> 1] >> 4 >= 8) {
//       chars[i] = chars[i].toUpperCase();
//     }
//     if ((hashed[i >> 1] & 0x0f) >= 8) {
//       chars[i + 1] = chars[i + 1].toUpperCase();
//     }
//   }

//   return '0x' + chars.join('');
// };

// export const sign = (
//   digest: bytes.Arrayish | string,
//   privateKey: string,
// ): bytes.Signature => {
//   if (!isPrivateKey(privateKey)) {
//     throw new Error(`${privateKey} is not PrivateKey`);
//   }

//   const keyPair = ec.keyFromPrivate(strip0x(privateKey), 'hex');
//   const signature = keyPair.sign(bytes.arrayify(digest), { canonical: true });
//   const publicKey = '0x' + keyPair.getPublic(true, 'hex');
//   const result = {
//     recoveryParam: signature.recoveryParam,
//     r: bytes.hexZeroPad('0x' + signature.r.toString(16), 32),
//     s: bytes.hexZeroPad('0x' + signature.s.toString(16), 32),
//     v: 27 + signature.recoveryParam,
//   };

//   if (verifySignature(digest, result, publicKey)) {
//     return result;
//   } else {
//     throw new Error('signing process failed');
//   }
// };

// export function getContractAddress(from: string, nonce: number): string {
//   if (!from) {
//     throw new Error('missing from address');
//   }

//   const addr = keccak256(
//     encode([from, bytes.stripZeros(bytes.hexlify(nonce))]),
//   );
//   return '0x' + addr.substring(26);
// }

// export function verifySignature(
//   digest: bytes.Arrayish,
//   signature: bytes.Signature,
//   publicKey: string,
// ): boolean {
//   return recoverPublicKey(digest, signature) === publicKey;
// }

// export function recoverPublicKey(
//   digest: bytes.Arrayish | string,
//   signature: bytes.Signature | string,
// ): string {
//   const sig = bytes.splitSignature(signature);
//   const rs = { r: bytes.arrayify(sig.r), s: bytes.arrayify(sig.s) };

//   ////
//   const recovered = ec.recoverPubKey(
//     bytes.arrayify(digest),
//     rs,
//     sig.recoveryParam,
//   );

//   const key = recovered.encode('hex', false);
//   const ecKey = ec.keyFromPublic(key, 'hex');
//   const publicKey = '0x' + ecKey.getPublic(true, 'hex');

//   ///

//   return publicKey;
// }

// export function recoverAddress(
//   digest: bytes.Arrayish | string,
//   signature: bytes.Signature | string,
// ): string {
//   return getAddressFromPublicKey(
//     recoverPublicKey(bytes.arrayify(digest) || new Uint8Array(), signature),
//   );
// }

// /**
//  * isValidChecksumAddress
//  *
//  * takes hex-encoded string and returns boolean if address is checksumed
//  *
//  * @param {string} address
//  * @returns {boolean}
//  */
// export const isValidChecksumAddress = (address: string): boolean => {
//   return (
//     isAddress(address.replace('0x', '')) &&
//     toChecksumAddress(address) === address
//   );
// };
