const AUTH_KEY='farm-manager-auth-v2';
export function getSession(){ try{return JSON.parse(localStorage.getItem(AUTH_KEY)||'null')}catch{return null} }
export function clearSession(){ localStorage.removeItem(AUTH_KEY); }
export function startLocalAdmin(){
  const session={mode:'local-admin',user:{id:'local-admin',name:'Admin',email:'',role:'ADMIN',organizationId:'local-admin-workspace'},farmId:'farm-sunyani'};
  localStorage.setItem(AUTH_KEY,JSON.stringify(session));
  return session;
}
async function authRequest(path,payload){ const r=await fetch(path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)}); const data=await r.json().catch(()=>({})); if(!r.ok) throw new Error(data.error||'AUTH_FAILED'); localStorage.setItem(AUTH_KEY,JSON.stringify(data)); return data; }
export async function login(email,password){ return authRequest('/api/auth/login',{email,password}); }
export async function registerOwner(payload){ return authRequest('/api/auth/register',payload); }
export async function activateStaff(payload){ return authRequest('/api/auth/activate-staff',payload); }
async function api(path,opts={}){ const s=getSession(); if(s?.mode==='local-admin') throw new Error('LOCAL_ADMIN_OFFLINE'); if(!s?.token) throw new Error('NOT_SIGNED_IN'); const r=await fetch(path,{...opts,headers:{...(opts.headers||{}),authorization:`Bearer ${s.token}`}}); if(r.status===401){clearSession();throw new Error('SESSION_EXPIRED');} const data=await r.json().catch(()=>({})); if(!r.ok) throw new Error(data.error||`CLOUD_${r.status}`); return data; }
export async function bootstrap(){ return api('/api/bootstrap'); }
export async function pushCommands(commands){ return api('/api/sync/push',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({commands})}); }
export async function pullCommands(since){ return api(`/api/sync/pull?since=${encodeURIComponent(since||'1970-01-01T00:00:00.000Z')}`); }
export async function getStaffAccess(){ return api('/api/staff/access'); }
export async function createStaffInvite(payload){ return api('/api/staff/invitations',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)}); }
export async function setStaffAccountStatus(userId,status){ return api('/api/staff/accounts/status',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({userId,status})}); }
export async function health(){ const r=await fetch('/api/health'); return r.json(); }
