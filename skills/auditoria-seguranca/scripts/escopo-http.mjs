// MIT. Controles locais; não validam a autorização real do operador ou a assinatura do JWT.
import { readFileSync } from 'node:fs';
export function lerJson(path) {
  const bytes = readFileSync(path);
  if (bytes.length > 262144) throw Error('entrada_limite');
  return JSON.parse(bytes.toString('utf8'));
}
export function preparar(envPath, args) {
  const index = args.indexOf('--scope');
  if (index < 0 || !args[index + 1]) throw Error('escopo_obrigatorio');
  const scope = lerJson(args[index + 1]);
  const envText = readFileSync(envPath);
  if (envText.length > 65536) throw Error('entrada_limite');
  const env = Object.fromEntries(envText.toString('utf8').split('\n').map(l => l.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/)).filter(Boolean).map(m => [m[1],m[2].replace(/^["']|["']$/g,'')]));
  const get = (...keys) => keys.map(k => env[k]).find(Boolean);
  const origin = new URL(get('VITE_SUPABASE_URL','NEXT_PUBLIC_SUPABASE_URL','SUPABASE_URL'));
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash || origin.origin !== scope.origin) throw Error('origem_invalida');
  const key = get('VITE_SUPABASE_ANON_KEY','VITE_SUPABASE_PUBLISHABLE_KEY','NEXT_PUBLIC_SUPABASE_ANON_KEY','NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY','SUPABASE_ANON_KEY');
  let legacy = false;
  if (!/^sb_publishable_[A-Za-z0-9_-]{8,}$/.test(key || '')) {
    const parts = (key || '').split('.');
    if (parts.length !== 3 || parts.some(p => !/^[A-Za-z0-9_-]+$/.test(p))) throw Error('chave_publica_invalida');
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (claims.role !== 'anon') throw Error('chave_publica_invalida');
    legacy = true;
  }
  if (scope.version !== 1 || !Array.isArray(scope.requests) || scope.requests.length > 100) throw Error('escopo_invalido');
  const execute = args.includes('--execute');
  const headers = { apikey: key, ...(legacy ? { Authorization: `Bearer ${key}` } : {}) };
  function validar(path, method = 'GET') {
    if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || /[\\#\r\n]/.test(path)) throw Error('caminho_invalido');
    const url = new URL(path, origin);
    if (url.origin !== origin.origin || url.pathname + url.search !== path) throw Error('caminho_invalido');
    const allowed = scope.requests.find(r => r.path === path && r.method === method);
    if (!allowed || !['GET','POST'].includes(method)) throw Error('fora_do_escopo');
    const rpc = url.pathname.startsWith('/rest/v1/rpc/');
    const effect = method !== 'GET' || rpc || url.pathname.startsWith('/functions/v1/');
    if (effect && !(allowed.fixture_only === true && scope.disposable_environment === true)) throw Error('efeito_sem_fixture');
    return url;
  }
  let count = 0;
  const deadline = Date.now() + 60000;
  async function pedir(path, options = {}) {
    const method = options.method || 'GET';
    const url = validar(path, method);
    if (!execute) throw Error('execucao_nao_autorizada');
    if (++count > 100 || Date.now() >= deadline) throw Error('execucao_limite');
    const signal = AbortSignal.timeout(Math.max(1, Math.min(8000, deadline - Date.now())));
    const response = await fetch(url.href, { ...options, method, headers: { ...headers, ...options.headers }, redirect:'error', signal });
    const reader = response.body?.getReader();
    let size = 0; const chunks = [];
    if (reader) {
      try {
        while (true) {
          const part = await reader.read();
          if (part.done) break;
          size += part.value.byteLength;
          if (size > 1048576) throw Error('resposta_limite');
          chunks.push(part.value);
        }
      } catch (error) { await reader.cancel().catch(() => {}); throw error; }
      finally { reader.releaseLock(); }
    }
    return { status:response.status, texto:Buffer.concat(chunks).toString('utf8'), total:response.headers.get('content-range') };
  }
  return { execute, validar, pedir };
}
export function falhar() { console.error('INDETERMINADO: entrada, escopo ou transporte inválido; nenhum conteúdo remoto registrado.'); process.exitCode = 2; }
