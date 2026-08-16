const DB_NAME = 'farm-manager-preview';
const DB_VERSION = 1;
const STORE = 'state';
let dbPromise;
let writeQueue = Promise.resolve();

function openDb() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => { dbPromise = null; reject(req.error); };
  });
  return dbPromise;
}

export async function loadState(seed, namespace = 'guest') {
  try {
    const db = await openDb();
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly');
      const req = tx.objectStore(STORE).get(`app:${namespace}`);
      req.onsuccess = () => resolve(req.result || seed);
      req.onerror = () => reject(req.error);
    });
  } catch {
    return seed;
  }
}

export async function saveState(state, namespace = 'guest') {
  const snapshot = structuredClone(state);
  const write = async () => {
    const db = await openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).put(snapshot, `app:${namespace}`);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  };
  writeQueue = writeQueue.catch(() => {}).then(write);
  return writeQueue;
}
