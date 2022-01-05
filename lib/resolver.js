import fetch from 'cross-fetch';

let TRUST_REGISTRY = {}
let LAST_FETCH = undefined;
const ONE_DAY_IN_MSECONDS = 86400000;

async function getJSON(url) {
    const res = await fetch(url);
      
    if (res.status >= 400) {
      //console.log(res);
      throw new Error("Bad response from server");
    }

    return await res.json();
} 

export async function resolveKey(kidIndex) {
  if (!TRUST_REGISTRY[kidIndex] && (!LAST_FETCH || new Date().getTime() > LAST_FETCH.getTime() + ONE_DAY_IN_MSECONDS )) {
    const start = Date.now()
    try {
      const res = await fetch('https://raw.githubusercontent.com/Path-Check/trust-registry/main/registry.json', {method: 'GET', mode: 'no-cors'})
      const data = await res.text()
      TRUST_REGISTRY = JSON.parse(data)["DIVOC"];
    } catch (e) {
      console.log(e);
    }

    LAST_FETCH = new Date();
  }

  if (TRUST_REGISTRY[kidIndex]) {
    return TRUST_REGISTRY[kidIndex];
  }

  return undefined;
}
