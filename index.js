import fs from 'fs';

const SECRET_KEY = new Uint8Array(
  '-72,-109,68,-63,74,27,-112,-69,-125,48,-82,82,51,-104,114,-20,-67,107,-87,42,-98,-13,-72,-88,-27,-23,-32,-79,-100,-31,-47,76'
    .split(',').map(e => parseInt(e, 10))
);

async function sha256(data) {
  let t = new Uint8Array(data);
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', t)));
}

async function hmacSha256(key, message) {
  let ipad = new Uint8Array(64);
  let opad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    let k = key.length > i ? key[i] : 0;
    ipad[i] = 0x36 ^ k;
    opad[i] = 0x5c ^ k;
  }
  let msgBytes = new TextEncoder().encode(message);
  function concat(a, b) {
    let r = new Uint8Array(a.length + b.length);
    r.set(a); r.set(b, a.length);
    return r;
  }
  let innerHash = await sha256(concat(ipad, msgBytes));
  return await sha256(concat(opad, innerHash));
}

async function deriveKey(secretKey) {
  let keyBytes = new TextEncoder().encode('Online Check-In');
  let hmacResult = await hmacSha256(keyBytes, '');
  let derivedKey = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    derivedKey[i] = secretKey[i] ^ hmacResult[i];
  }
  return derivedKey;
}

async function generateICSSignature(message) {
  let derivedKey = await deriveKey(SECRET_KEY);
  let hmac = await hmacSha256(derivedKey, message);
  return btoa(hmac.map(e => String.fromCodePoint(e)).join(''))
    .replaceAll('+', '-')
    .replaceAll('/', '_');
}

async function getWaitTimes(storeNumbers) {
  let body = JSON.stringify(storeNumbers.map(e => ({ storeNumber: e })));
  let timestamp = new Date().getTime().toString();
  let signature = await generateICSSignature(`${timestamp}${body}`);
  let url = `https://www.stylewaretouch.net/api/store/waitTime?t=${timestamp}&s=${signature}`;
  let response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body
  });
  return response.json();
}

// --- Main ---
const STORES = ['9814'];
const LOG_FILE = 'wait_times.csv';

(async () => {
  try {
    const data = await getWaitTimes(STORES);
    const timestamp = new Date().toISOString();

    // Debug: print raw response so we can see structure
    console.log('Raw response:', JSON.stringify(data, null, 2));

    // Try to find the array of stores in common response shapes
    let stores = Array.isArray(data) ? data
               : Array.isArray(data?.stores) ? data.stores
               : Array.isArray(data?.data) ? data.data
               : Array.isArray(data?.results) ? data.results
               : Array.isArray(data?.waitTimes) ? data.waitTimes
               : null;

    if (!stores) {
      throw new Error('Could not find store array in response. See raw response above.');
    }

    // Create CSV header if file doesn't exist
    if (!fs.existsSync(LOG_FILE)) {
      fs.writeFileSync(LOG_FILE, 'timestamp,storeNumber,waitTime,raw\n');
    }

    const rows = stores.map(entry =>
      `${timestamp},${entry.storeNumber ?? ''},${entry.waitTime ?? ''},"${JSON.stringify(entry).replaceAll('"', '""')}"`
    ).join('\n') + '\n';

    fs.appendFileSync(LOG_FILE, rows);
    console.log(`Logged ${stores.length} stores at ${timestamp}`);
  } catch (err) {
    console.error('Error:', err);
    process.exit(1);
  }
})();
