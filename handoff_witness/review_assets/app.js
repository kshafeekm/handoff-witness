'use strict';
let csrf = '';
const cards = new Map();
const $ = id => document.getElementById(id);
async function api(path, body) {
  const response = await fetch(path, body === undefined ? {cache:'no-store'} : {
    method:'POST', headers:{'Content-Type':'application/json','X-Review-CSRF':csrf}, body:JSON.stringify(body)
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Review service unavailable');
  return result;
}
function notice(error) { $('message').textContent = error ? error.message : ''; }
function node(tag, text, className) {
  const el = document.createElement(tag); el.textContent = text;
  if (className) el.className = className;
  return el;
}
function card(item) {
  const el = node('article','','request'); el.dataset.reviewId = item.id;
  const top = node('div','','request-top');
  top.append(node('span',item.binding.method,'method'),node('span','','timer'));
  el.append(top,node('p',item.binding.url,'destination'),node('p','Approve only if you expect this destination and method. Body and headers are bound by hashes; their contents are not displayed here.','explanation'));
  const details = node('details',''); details.append(node('summary','Request binding details'));
  const dl = node('dl','');
  for (const key of ['session','request_id','body_sha256','headers_sha256']) dl.append(node('dt',key.replaceAll('_',' ')),node('dd',item.binding[key]));
  details.append(dl); el.append(details);
  const actions = node('div','','actions');
  const approve = node('button','Approve once with passkey'), deny = node('button','Deny','deny');
  async function act(action) {
    approve.disabled = deny.disabled = true; notice(null);
    try {
      if (action === 'deny') await api('/api/deny',{id:item.id});
      else {
        const options = await api('/api/approve/options',{id:item.id});
        const credential = await navigator.credentials.get({publicKey:PublicKeyCredential.parseRequestOptionsFromJSON(options.publicKey)});
        await api('/api/approve/finish',{id:item.id,credential:credential.toJSON()});
      }
      await refresh();
    } catch (error) { notice(error); }
    finally { approve.disabled = deny.disabled = false; }
  }
  approve.addEventListener('click',()=>act('approve')); deny.addEventListener('click',()=>act('deny'));
  actions.append(approve,deny); el.append(actions); return el;
}
async function refresh() {
  const state = await api('/api/state');
  $('connection').textContent = state.enrolled ? 'Passkey ready · approval required' : 'Local session connected';
  $('enrollment').hidden = state.enrolled;
  $('count').textContent = `${state.pending.length} request${state.pending.length === 1 ? '' : 's'}`;
  $('empty').hidden = state.pending.length > 0;
  const ids = new Set(state.pending.map(item=>item.id));
  for (const [id,el] of cards) if (!ids.has(id)) { el.remove(); cards.delete(id); }
  for (const item of state.pending) {
    if (!cards.has(item.id)) { const el = card(item); cards.set(item.id,el); $('queue').append(el); }
    cards.get(item.id).querySelector('.timer').textContent = `${item.seconds_remaining}s remaining`;
  }
  const labels = {credential_verified:'Credential approved for one attempt',denied:'Request denied',expired:'Request expired'};
  $('history').replaceChildren(...(state.events.length ? state.events.slice().reverse().map(e=>node('li',`${labels[e.status] || e.status} · ${e.id.slice(0,8)}`)) : [node('li','No decisions yet.')]));
}
$('enroll').addEventListener('click',async()=>{
  $('enroll').disabled = true; notice(null);
  try {
    const options = await api('/api/register/options',{});
    const credential = await navigator.credentials.create({publicKey:PublicKeyCredential.parseCreationOptionsFromJSON(options)});
    await api('/api/register/finish',{credential:credential.toJSON()}); await refresh();
  } catch(error) { notice(error); }
  finally { $('enroll').disabled = false; }
});
async function start() {
  const token = location.hash.slice(1);
  history.replaceState(null,'','/');
  try {
    const session = token ? await api('/api/session',{token}) : await api('/api/session');
    csrf = session.csrf; await refresh();
    setInterval(()=>refresh().catch(error=>{ $('connection').textContent='Disconnected · requests remain blocked'; notice(error); }),750);
  } catch(error) { $('connection').textContent='Session unavailable'; notice(error); }
}
start();
