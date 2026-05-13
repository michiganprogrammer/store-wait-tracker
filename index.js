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
// Updated with all salon numbers from the dearborn.json file
const STORES = [
  '9814', '9130', '1182', '1734', '1729', '1742', '1735', '1994', '3824', '9082',
  '8687', '1728', '7737', '0571', '9135', '9077', '9789', '9487', '3621', '2375',
  '9896', '1743', '2683', '1736', '1739', '9008', '9786', '1750', '9092', '3346',
  '9087', '0934', '1727', '7066', '9012', '9094', '9879', '2373', '1744', '8974',
  '1762', '1732', '9138', '9423', '9080', '9817', '3000', '8773', '9476', '9888'
];

const LOG_FILE = 'wait_times.csv';
const TZ = 'America/Detroit';

function getDateParts(date) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: TZ,
    weekday: 'long',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: false
  }).formatToParts(date);

  const get = (type) => parts.find(p => p.type === type).value;
  const day = get('weekday');
  const dateStr = `${get('year')}-${get('month')}-${get('day')}`;
  let hour = get('hour');
  if (hour === '24') hour = '00'; 
  const time = `${hour}:${get('minute')}`;
  return { day, date: dateStr, time };
}

(async () => {
  try {
    const data = await getWaitTimes(STORES);
    const now = new Date();
    const { day, date, time } = getDateParts(now);

    let stores = Array.isArray(data) ? data
               : Array.isArray(data?.stores) ? data.stores
               : Array.isArray(data?.data) ? data.data
               : Array.isArray(data?.results) ? data.results
               : Array.isArray(data?.waitTimes) ? data.waitTimes
               : null;

    if (!stores) {
      console.log('Raw response:', JSON.stringify(data, null, 2));
      throw new Error('Could not find store array in response.');
    }

    const lookup = {};
    for (const s of stores) {
      lookup[s.storeNumber] = s.estimatedWaitMinutes ?? '';
    }

    // Create file and header if it doesn't exist
    if (!fs.existsSync(LOG_FILE)) {
      fs.writeFileSync(LOG_FILE, `day,date,time,${STORES.join(',')}\n`);
    }

    // Map each store in our STORES array to its wait time found in the API response
    const row = `${day},${date},${time},${STORES.map(num => lookup[num] ?? '').join(',')}\n`;
    fs.appendFileSync(LOG_FILE, row);

    console.log(`Logged wait times for ${STORES.length} stores at ${time}`);
  } catch (err) {
    console.error('Error:', err);
    process.exit(1);
  }
})();
