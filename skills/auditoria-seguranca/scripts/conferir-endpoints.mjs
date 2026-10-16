// Plano por padrão. Rede apenas com --scope escopo.json --execute.
import { lerJson, preparar, falhar } from './escopo-http.mjs';
try {
  const [envPath, casosPath, ...args] = process.argv.slice(2);
  const client = preparar(envPath, args);
  const casos = lerJson(casosPath);
  if (!Array.isArray(casos) || !casos.length || casos.length > 100) throw Error('casos_invalidos');
  for (const c of casos) {
    client.validar(c.caminho, c.metodo || 'GET');
    if (!Array.isArray(c.esperado) || !c.esperado.length || c.esperado.some(s => !Number.isInteger(s) || s < 100 || s > 599) || (c.nao_conter && (!Array.isArray(c.nao_conter) || c.nao_conter.some(t => typeof t !== 'string' || !t)))) throw Error('caso_invalido');
  }
  if (!client.execute) console.log(`PLANO: ${casos.length} casos; nenhuma requisição enviada.`);
  else {
    let falhas = 0;
    for (const [indice, c] of casos.entries()) {
      const method = c.metodo || 'GET';
      const r = await client.pedir(c.caminho, { method, ...(method === 'POST' ? {headers:{'Content-Type':'application/json'}, body:JSON.stringify(c.corpo ?? {})} : {}) });
      const vazou = (c.nao_conter || []).filter(t => r.texto.toLowerCase().includes(t.toLowerCase())).length;
      const ok = c.esperado.includes(r.status) && !vazou;
      if (!ok) falhas++;
      console.log(`${ok ? 'OK' : 'FALHA'} caso ${indice + 1}: status=${r.status}; marcadores_proibidos=${vazou}`);
    }
    console.log(`${casos.length - falhas} de ${casos.length} como esperado. Isso não certifica RLS.`);
    process.exitCode = falhas ? 1 : 0;
  }
} catch { falhar(); }
