# Fork de estudo Radar — Supabase

Origem: dmanske/auditoria-seguranca-supabase, commit 5542c72a933a4c9ebfccb07f5c48f591d1cbd387. MIT de Daniel Manske preservada. Fork criado com todas as branches: no momento da criação, apenas main e nenhum tag foram anunciados pelo Git. Histórico de quatro commits preservado. Incidentes e resultados citados no guia são relatos upstream, não medições do Radar.

## Uso no ChatGPT/Codex

Leia a skill e forneça somente código e metadados autorizados, sem `.env`, dados pessoais ou credenciais. Peça primeiro um plano por recurso/perfil. O catálogo não substitui revisão humana ou testes de RLS no banco descartável.

O instalador deste fork apenas imprime um plano local. Não executa npx, instala skills globais ou busca dependências externas. Revise o checkout fixado por SHA antes de copiar uma skill.

## Scripts HTTP: mudança de contrato

Requer Node 22+ ou 24 LTS. Nenhum serviço real foi acessado na validação. Prepare uma cópia privada de `scripts/escopo.exemplo.json` com origem exata e cada caminho/método autorizado. O arquivo deve ficar fora do Git, assim como `.env` e relatórios reais.

```sh
node skills/auditoria-seguranca/scripts/conferir-endpoints.mjs fixture.env casos.json --scope escopo.json
node skills/auditoria-seguranca/scripts/teste-visitante.mjs fixture.env alvos.json resultado.json --scope escopo.json
```

Os comandos acima só validam o plano. Acrescente `--execute` após revisar o escopo, exclusivamente em ambiente autorizado. Endpoints Functions, RPC e POST exigem `disposable_environment: true` e `fixture_only: true` por requisição. Esses campos são declarações do operador: não provam isolamento ou ausência de efeitos externos. RPCs também precisam continuar estáveis/imutáveis e sem argumentos. Não inclua pagamentos, cron, WhatsApp ou backups reais. Os exemplos antigos de endpoints não estão autorizados automaticamente.

Padrão GET sem corpo; apenas GET/POST; até 100 casos/recursos, entrada JSON 256 KiB, `.env` 64 KiB, resposta 1 MiB, 8 segundos por requisição e orçamento de 60 segundos por execução. Redirects recusados. Excesso, falha ou JSON remoto inválido no visitante = saída 2 (indeterminado), nunca aprovação. Endpoint com status/marker divergente = saída 1; sucesso das verificações configuradas = 0. Marcadores só são avaliados dentro do corpo completo aceito pelo limite. O relatório do visitante é criado sem sobrescrever arquivo existente e com modo 0600; nomes de recursos/colunas continuam sendo metadados potencialmente privados.

Rejeita `sb_secret_` e JWT com papel diferente de anon. A inspeção local de claims não verifica assinatura nem validade; não autentica uma pessoa. Chaves publishable seguem apenas no cabeçalho apikey. JWT legado anon também segue em Authorization. URL deve ser HTTPS e coincidir com a origem aprovada; DNS, proxy e propriedade do destino não são atestados.

## Catálogo, SQL e integração

A consulta §2d agora classifica UPDATE sem WITH CHECK como candidato: PostgreSQL pode reutilizar USING. A §9 não retorna trechos de comandos cron. Revise composição de policies, grants e testes por papel. Não aplique em lote padrões SQL: guards de UID nulo, search_path, SECURITY DEFINER, views invoker e invalidação de sessões precisam de contexto e ACL reais.

Extração recomendada: planejamento offline no Security Workbench existente, sem incorporar executor, servidor MCP, LLM, n8n ou instalação automática. Cada produto conserva suas próprias migrations e testes de RLS. Tabela vazia, resposta 401 e ausência de padrões pessoais não comprovam isolamento. Revogar refresh tokens não garante invalidação instantânea de todos os access JWTs.

## Verificação reproduzível

```sh
python3 -m unittest discover -s tests -v
```

17 testes offline, com fetch substituído integralmente por fixtures e Deno simulado. Cobrem regressões dos logs, propagação de erros Deno, truncamento, plano sem rede, chaves, origem, escopo inteiro antes da execução, efeitos, limite de resposta, headers e RPC escalar. Deno real, SQL/RLS, navegador e produção não validados. O scanner de segredos é heurístico e não substitui Gitleaks/varredura de histórico. CI usa Python 3.12 e o Node fornecido pelo runner, cuja versão é registrada; não fixa patch do runtime.

Rollback: conservar main intacta e fechar a PR. Nenhum banco ou arquivo de produto é alterado por esta entrega.
