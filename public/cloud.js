const AUTH_KEY='farm-manager-auth-v2';
export function getSession(){ try{return JSON.parse(localStorage.getItem(AUTH_KEY)||'null')}catch{return null} }
export function clearSession(){ localStorage.removeItem(AUTH_KEY); }
export function startLocalAdmin(){
  const session={mode:'local-admin',user:{id:'local-admin',name:'Admin',email:'',role:'ADMIN',organizationId:'local-admin-workspace'},farmId:'farm-sunyani'};
  localStorage.setItem(AUTH_KEY,JSON.stringify(session));
  return session;
}
async function authRequest(path,payload){ const r=await fetch(path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)}); const data=await r.json().catch(()=>({})); if(!r.ok){const error=new Error(data.error||'AUTH_FAILED');error.retryAfterSeconds=data.retryAfterSeconds;throw error;}if(data.token)localStorage.setItem(AUTH_KEY,JSON.stringify(data));return data; }
export async function login(email,password){ return authRequest('/api/auth/login',{email,password}); }
export async function registerOwner(payload){ return authRequest('/api/auth/register',payload); }
export async function activateStaff(payload){ return authRequest('/api/auth/activate-staff',payload); }
export async function verifyMfa(challengeToken,code){return authRequest('/api/auth/mfa/verify',{challengeToken,code});}
function deviceHeaders(){let id=localStorage.getItem('farm-manager-device-id');if(!id){id=crypto.randomUUID();localStorage.setItem('farm-manager-device-id',id);}const touch=/iPhone|iPad/.test(navigator.userAgent)?'iPhone or iPad':/Android/.test(navigator.userAgent)?'Android phone':/Windows/.test(navigator.userAgent)?'Windows computer':/Mac/.test(navigator.userAgent)?'Mac computer':'Web device';return{'x-device-id':id,'x-device-name':touch};}
async function api(path,opts={}){ const s=getSession(); if(s?.mode==='local-admin') throw new Error('LOCAL_ADMIN_OFFLINE'); if(!s?.token) throw new Error('NOT_SIGNED_IN'); const r=await fetch(path,{...opts,headers:{...(opts.headers||{}),...deviceHeaders(),authorization:`Bearer ${s.token}`}}); if(r.status===401){clearSession();throw new Error('SESSION_EXPIRED');} const data=await r.json().catch(()=>({})); if(!r.ok){const error=new Error(data.error||`CLOUD_${r.status}`);error.details=data;throw error;} return data; }
export async function bootstrap(){ return api('/api/bootstrap'); }
export async function pushCommands(commands){ return api('/api/sync/push',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({commands})}); }
export async function pullCommands(since){ return api(`/api/sync/pull?since=${encodeURIComponent(since||'1970-01-01T00:00:00.000Z')}`); }
export async function getStaffAccess(){ return api('/api/staff/access'); }
export async function createStaffInvite(payload){ return api('/api/staff/invitations',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)}); }
export async function setStaffAccountStatus(userId,status){ return api('/api/staff/accounts/status',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({userId,status})}); }
export async function getSecurityStatus(){return api('/api/security/status');}
export async function beginMfaSetup(password){return api('/api/security/mfa/setup',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password})});}
export async function enableMfa(code){return api('/api/security/mfa/enable',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({code})});}
export async function disableMfa(password,code){return api('/api/security/mfa/disable',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password,code})});}
export async function changePassword(currentPassword,newPassword,code){return api('/api/security/password',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({currentPassword,newPassword,code})});}
export async function revokeSessions(payload){return api('/api/security/sessions/revoke',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});}
export async function logoutCloud(){return api('/api/auth/logout',{method:'POST'});}
export async function getSecurityControlCenter(){return api('/api/security/control-center');}
export async function updateStaffPermissions(userId,permissions){return api('/api/security/permissions',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({userId,permissions})});}
export async function decideSecurityApproval(approvalId,decision){return api('/api/security/approvals/decision',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({approvalId,decision})});}
export async function uploadComplianceFile(file){const body=new FormData();body.append('file',file);return api('/api/compliance/files',{method:'POST',body});}
export async function downloadComplianceFile(documentId){const s=getSession();if(!s?.token)throw new Error('NOT_SIGNED_IN');const r=await fetch(`/api/compliance/files/${encodeURIComponent(documentId)}`,{headers:{authorization:`Bearer ${s.token}`}});if(!r.ok)throw new Error((await r.json().catch(()=>({}))).error||'FILE_UNAVAILABLE');return r.blob();}
export async function health(){ const r=await fetch('/api/health'); return r.json(); }
