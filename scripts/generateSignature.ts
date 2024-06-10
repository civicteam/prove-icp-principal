import { Ed25519KeyIdentity } from '@dfinity/identity';
import { Buffer } from 'buffer';

async function generateSignature() {
  // Create a new identity
  const identity = Ed25519KeyIdentity.generate();

  // Get the public and private keys
  const publicKey = identity.getPublicKey().toDer();
  const privateKey = identity.getKeyPair().secretKey;

  // Your challenge message
  const challenge = 'YSBjaGFsbGVuZ2UsIGkuZS4gYSBzdHJpbmcgb2YgYXQgbGVhc3QgMzIgYnl0ZXM=';
  const challengeBuffer = Buffer.from(challenge, 'base64');

  // Sign the challenge
  const signature = await identity.sign(challengeBuffer);

  // Log the keys and signature
  console.log('Public Key (DER):', Buffer.from(publicKey).toString('hex'));
  console.log('Private Key:', Buffer.from(privateKey).toString('hex'));
  console.log('Signature:', Buffer.from(signature).toString('hex'));
}

generateSignature().catch(console.error);
