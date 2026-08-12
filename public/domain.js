export const newId = () => {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  const bytes = new Uint8Array(16);
  if (globalThis.crypto?.getRandomValues) globalThis.crypto.getRandomValues(bytes);
  else for (let i=0;i<bytes.length;i++) bytes[i]=Math.floor(Math.random()*256);
  bytes[6]=(bytes[6]&15)|64; bytes[8]=(bytes[8]&63)|128;
  const hex=[...bytes].map(value=>value.toString(16).padStart(2,'0')).join('');
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
};

export function calculateFlockPopulation(events, flockId) {
  return events.filter(e => !flockId || e.flockId === flockId).reduce((sum, e) => sum + e.quantityDelta, 0);
}

export function recordMortality(flockId, quantity, events) {
  if (!Number.isInteger(quantity) || quantity <= 0) throw new Error('Mortality must be a positive whole number.');
  const available = calculateFlockPopulation(events, flockId);
  if (quantity > available) throw new Error(`Cannot record ${quantity} deaths. Only ${available} birds remain.`);
  return { id:newId(), flockId, type:'MORTALITY', quantityDelta:-quantity, eventDate:new Date().toISOString() };
}

export function calculateStockBalance(movements, itemId, locationId) {
  return movements.filter(m => m.inventoryItemId === itemId).reduce((balance, m) => {
    if (!locationId) return balance + m.quantityDelta;
    if (m.toLocationId === locationId) balance += Math.abs(m.quantityDelta);
    if (m.fromLocationId === locationId) balance -= Math.abs(m.quantityDelta);
    if (!m.fromLocationId && !m.toLocationId) balance += m.quantityDelta;
    return balance;
  }, 0);
}

export function issueFeed({ itemId, quantity, fromLocationId, movements, flockId }) {
  if (!(quantity > 0)) throw new Error('Feed quantity must be greater than zero.');
  const available = calculateStockBalance(movements, itemId, fromLocationId);
  if (quantity > available) throw new Error(`Insufficient feed stock. Available: ${available} kg.`);
  return {
    id:newId(), inventoryItemId:itemId, fromLocationId, quantityDelta:-quantity,
    type:'ISSUE_TO_FLOCK', occurredAt:new Date().toISOString(), relatedFlockId: flockId
  };
}
