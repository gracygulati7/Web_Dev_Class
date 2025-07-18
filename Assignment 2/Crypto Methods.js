const crypto = require('crypto');
const hash=crypto.createHash('sha256').update('Hello cyctro').digest('hex');
console.log(hash);

// crypto for check prime
const checkPrime=crypto.checkPrimeSync(4n);
console.log(checkPrime); 

//crypto for constant
console.log(crypto.constants);

console.log(crypto.constants.RSA_PKCS1_PADDING); 

const token = crypto.randomBytes(8).toString('hex');
console.log(token);



const secret = 'mySecretKey';
const message = 'This is a message';


const hmac = crypto.createHmac('sha256', secret).update(message).digest('hex');

console.log('HMAC:', hmac);


const key = crypto.randomBytes(32); // For aes-256
const iv = crypto.randomBytes(16); // 16-byte IV

const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
let encrypted = cipher.update('Secret message', 'utf8', 'hex');
encrypted += cipher.final('hex');

const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
let decrypted = decipher.update(encrypted, 'hex', 'utf8');
decrypted += decipher.final('utf8');

console.log('Encrypted:', encrypted);
console.log('Decrypted:', decrypted);
