/* ================= SHARED: SUPABASE + SESSION (used by every page) ================= */
const SUPABASE_URL = 'https://xljkmqmuqxxqlmbrwrtv.supabase.co';
const SUPABASE_KEY = 'sb_publishable_QVwXY0nYUUAd36kWXQCFNg_a5SKV-N9';
const ADMIN_EMAILS = ['gignary56@gmail.com'];
let accessToken = null;
let refreshTokenValue = null;
let tokenExpiresAt = 0; // ms epoch timestamp

/* Wraps fetch with a timeout so buttons never get stuck on "Logging in..." forever
   if Supabase doesn't respond (paused project, bad key, no internet, etc). */
async function fetchWithTimeout(url, options, timeoutMs){
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs || 15000);
  try{
    return await fetch(url, Object.assign({}, options, { signal: controller.signal }));
  } catch(err){
    if(err.name === 'AbortError'){
      throw new Error('Server took too long to respond. Your Supabase project may be paused, or check your internet connection.');
    }
    throw err;
  } finally {
    clearTimeout(id);
  }
}

function errMsg(e){
  if(!e) return 'Unknown error';
  return e.message || e.msg || e.error_description || e.error || (e.details) || JSON.stringify(e);
}
function showToast(msg, isError){
  const t = document.getElementById('toast');
  if(!t){ console.log(msg); return; }
  t.textContent = msg;
  t.className = 'toast show' + (isError ? ' error' : '');
  clearTimeout(t._timer);
  t._timer = setTimeout(()=> t.classList.remove('show'), 6000);
}
function authHeaders(extra){
  return Object.assign({
    'apikey': SUPABASE_KEY,
    'Authorization': 'Bearer ' + (accessToken || SUPABASE_KEY)
  }, extra || {});
}

/* Refreshes the Supabase access token using the stored refresh token.
   Called automatically before it expires, and as a retry when a request comes back 401. */
async function refreshAccessToken(){
  if(!refreshTokenValue) return false;
  try{
    const res = await fetchWithTimeout(SUPABASE_URL + '/auth/v1/token?grant_type=refresh_token', {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'apikey': SUPABASE_KEY },
      body: JSON.stringify({ refresh_token: refreshTokenValue })
    });
    const json = await res.json().catch(()=>({}));
    if(!res.ok || !json.access_token) return false;
    accessToken = json.access_token;
    refreshTokenValue = json.refresh_token || refreshTokenValue;
    tokenExpiresAt = json.expires_in ? (Date.now() + json.expires_in * 1000) : (Date.now() + 55*60*1000);
    try{
      const raw = localStorage.getItem('gignary_session');
      const parsed = raw ? JSON.parse(raw) : {};
      parsed.token = accessToken; parsed.refreshToken = refreshTokenValue; parsed.expiresAt = tokenExpiresAt;
      localStorage.setItem('gignary_session', JSON.stringify(parsed));
    } catch(e){}
    return true;
  } catch(err){
    return false;
  }
}

/* Call once on page load (after loadSession) to make sure the token is still valid
   before using it — refreshes it if it's expired or about to expire. */
async function ensureValidSession(){
  if(!refreshTokenValue) return true;
  if(!tokenExpiresAt || Date.now() >= tokenExpiresAt - 60000){
    return await refreshAccessToken();
  }
  return true;
}

/* Does an authenticated fetch; if the server says the token expired (401),
   refreshes it once and retries automatically. */
async function authFetchWithRefresh(url, method, headersExtra, body){
  const doFetch = () => fetchWithTimeout(url, { method, headers: authHeaders(headersExtra), body });
  let res = await doFetch();
  if(res.status === 401 && refreshTokenValue){
    if(await refreshAccessToken()) res = await doFetch();
  }
  return res;
}
async function sbSignUp(email, password, name){
  try{
    const res = await fetchWithTimeout(SUPABASE_URL + '/auth/v1/signup', {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'apikey': SUPABASE_KEY },
      body: JSON.stringify({ email, password, data: { name } })
    });
    const json = await res.json().catch(()=>({}));
    if(!res.ok) return { error: json };
    if(json.access_token){
      accessToken = json.access_token;
      refreshTokenValue = json.refresh_token || null;
      tokenExpiresAt = json.expires_in ? (Date.now() + json.expires_in * 1000) : (Date.now() + 55*60*1000);
    }
    return { data: json };
  } catch(err){
    return { error: { message: err.message } };
  }
}
async function sbSignIn(email, password){
  try{
    const res = await fetchWithTimeout(SUPABASE_URL + '/auth/v1/token?grant_type=password', {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'apikey': SUPABASE_KEY },
      body: JSON.stringify({ email, password })
    });
    const json = await res.json().catch(()=>({}));
    if(!res.ok) return { error: json };
    accessToken = json.access_token;
    refreshTokenValue = json.refresh_token || null;
    tokenExpiresAt = json.expires_in ? (Date.now() + json.expires_in * 1000) : (Date.now() + 55*60*1000);
    return { data: json };
  } catch(err){
    return { error: { message: err.message } };
  }
}
function sbSignOut(){ accessToken = null; refreshTokenValue = null; tokenExpiresAt = 0; }

/* Updates the logged-in user's own auth record (email and/or password) via Supabase Auth.
   Changing email triggers Supabase to send a confirmation link to the new address. */
async function sbUpdateUser(patch){
  try{
    const res = await fetchWithTimeout(SUPABASE_URL + '/auth/v1/user', {
      method: 'PUT',
      headers: { 'Content-Type':'application/json', 'apikey': SUPABASE_KEY, 'Authorization': 'Bearer ' + accessToken },
      body: JSON.stringify(patch)
    });
    const json = await res.json().catch(()=>({}));
    if(!res.ok) return { error: json };
    return { data: json };
  } catch(err){
    return { error: { message: err.message } };
  }
}

/* Sends a password-reset email. The link in that email opens reset.html. */
async function sbResetPassword(email){
  try{
    const redirectTo = window.location.origin + '/reset.html';
    const res = await fetchWithTimeout(SUPABASE_URL + '/auth/v1/recover?redirect_to=' + encodeURIComponent(redirectTo), {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'apikey': SUPABASE_KEY },
      body: JSON.stringify({ email })
    });
    const json = await res.json().catch(()=>({}));
    if(!res.ok) return { error: json };
    return { data: json };
  } catch(err){
    return { error: { message: err.message } };
  }
}

function signInWithGoogle(){
  const redirectTo = window.location.origin + '/dashboard.html';
  window.location.href = SUPABASE_URL + '/auth/v1/authorize?provider=google&redirect_to=' + encodeURIComponent(redirectTo);
}

async function handleOAuthRedirect(){
  const hash = window.location.hash;
  if(!hash || !hash.includes('access_token')) return false;
  const params = new URLSearchParams(hash.substring(1));
  const token = params.get('access_token');
  const refresh = params.get('refresh_token');
  const expiresIn = params.get('expires_in');
  if(!token) return false;

  accessToken = token;
  const res = await fetch(SUPABASE_URL + '/auth/v1/user', {
    headers: { 'Authorization': 'Bearer ' + token, 'apikey': SUPABASE_KEY }
  });
  const userData = await res.json().catch(()=>({}));
  if(!res.ok || !userData.id) return false;

  const googleName = (userData.user_metadata && (userData.user_metadata.full_name || userData.user_metadata.name)) || userData.email.split('@')[0];
  const googleAvatar = userData.user_metadata && userData.user_metadata.avatar_url;

  const user = { id: userData.id, name: googleName, email: userData.email, avatarUrl: googleAvatar || null };
  saveSession(user, token, refresh, expiresIn ? parseInt(expiresIn, 10) : null);
  if(userData.created_at && (Date.now() - new Date(userData.created_at).getTime()) < 60000){
    try{ localStorage.setItem('gignary_just_signed_up', '1'); }catch(e){}
  }
  history.replaceState(null, '', window.location.pathname);
  return true;
}
async function sbSelect(table, query){
  try{
    const res = await authFetchWithRefresh(SUPABASE_URL + '/rest/v1/' + table + '?' + (query || ''), 'GET');
    const json = await res.json().catch(()=>([]));
    if(!res.ok) return { error: json };
    return { data: json };
  } catch(err){
    return { error: { message: err.message } };
  }
}
async function sbInsert(table, row){
  try{
    const res = await authFetchWithRefresh(SUPABASE_URL + '/rest/v1/' + table, 'POST', { 'Content-Type':'application/json', 'Prefer':'return=representation' }, JSON.stringify(row));
    const json = await res.json().catch(()=>({}));
    if(!res.ok) return { error: json };
    return { data: Array.isArray(json) ? json[0] : json };
  } catch(err){
    return { error: { message: err.message } };
  }
}
async function sbUpdate(table, id, patch){
  try{
    const res = await authFetchWithRefresh(SUPABASE_URL + '/rest/v1/' + table + '?id=eq.' + id, 'PATCH', { 'Content-Type':'application/json', 'Prefer':'return=representation' }, JSON.stringify(patch));
    const json = await res.json().catch(()=>({}));
    if(!res.ok) return { error: json };
    return { data: json };
  } catch(err){
    return { error: { message: err.message } };
  }
}
async function sbUpload(path, file){
  const encodedPath = path.split('/').map(encodeURIComponent).join('/');
  try{
    const res = await authFetchWithRefresh(SUPABASE_URL + '/storage/v1/object/gig-media/' + encodedPath, 'POST', { 'Content-Type': file.type || 'application/octet-stream' }, file);
    const json = await res.json().catch(()=>({}));
    if(!res.ok) return { error: json };
    return { data: json };
  } catch(err){
    return { error: { message: err.message } };
  }
}
function sbPublicUrl(path){
  const encodedPath = path.split('/').map(encodeURIComponent).join('/');
  return SUPABASE_URL + '/storage/v1/object/public/gig-media/' + encodedPath;
}
async function sbDelete(table, id){
  try{
    const res = await authFetchWithRefresh(SUPABASE_URL + '/rest/v1/' + table + '?id=eq.' + id, 'DELETE');
    if(!res.ok){
      const json = await res.json().catch(()=>({}));
      return { error: json };
    }
    return { data: true };
  } catch(err){
    return { error: { message: err.message } };
  }
}

/* ================= SESSION (kept in localStorage so login carries across pages) ================= */
function saveSession(user, token, refreshTok, expiresIn){
  accessToken = token;
  refreshTokenValue = (refreshTok !== undefined && refreshTok !== null) ? refreshTok : refreshTokenValue;
  tokenExpiresAt = expiresIn ? (Date.now() + expiresIn * 1000) : (tokenExpiresAt || (Date.now() + 55*60*1000));
  try{ localStorage.setItem('gignary_session', JSON.stringify({ user, token, refreshToken: refreshTokenValue, expiresAt: tokenExpiresAt })); }
  catch(e){ console.error('Could not save session', e); }
}
function loadSession(){
  try{
    const raw = localStorage.getItem('gignary_session');
    if(!raw) return null;
    const parsed = JSON.parse(raw);
    accessToken = parsed.token || null;
    refreshTokenValue = parsed.refreshToken || null;
    tokenExpiresAt = parsed.expiresAt || 0;
    return parsed;
  }catch(e){ return null; }
}
function clearSession(){
  accessToken = null; refreshTokenValue = null; tokenExpiresAt = 0;
  try{ localStorage.removeItem('gignary_session'); }catch(e){}
}
