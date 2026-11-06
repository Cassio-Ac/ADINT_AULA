# A escada do MCP — ADINT 2026

Quatro servidores MCP, do mínimo possível até um agente com base de conhecimento.
Todos fazem a **mesma coisa** (um `ping`), de propósito: assim o que muda de um
degrau para o outro é só o conceito.

MCP não é mágica de IA. É **JSON-RPC 2.0 em cima de stdin/stdout**. O
`fala_com_mcp.py` prova isso sem nenhum LLM no caminho.

---

## Antes de começar

O `mcp` já está no `requirements.txt` da raiz (fixado em `mcp<2`):

```bash
pip install -r requirements.txt
```

Conferido em 05/11/2026 com `mcp 1.30.0` e Python 3.12.3. A 2.x renomeou
`FastMCP` → `MCPServer`; estes scripts usam a API v1.

---

## A ordem

| # | script | o que entra de novo |
|---|---|---|
| 1 | `mcp_1_ping.py` | o servidor mínimo: **uma função + um decorador** |
| 2 | `mcp_2_argumento.py` | argumento → **a docstring e o tipo viram o schema** |
| 3 | `mcp_3_agente.py` | ferramenta → **agente**: devolve veredito, não texto |
| 4 | `mcp_4_kb.py` | o conhecimento sai do código e vira **dado auditável** |

Apoio:

- `sem_bom.py` — três bytes que o `wsl.exe` injeta e que matam o handshake.
  Leia o cabeçalho: é um caso de depuração por bytes, não por mensagem de erro.
- `claude_mcp.json` — a configuração pronta, com os quatro degraus.
- `../fala_com_mcp.py` — o cliente MCP na mão, sem LLM.

---

## Ver o protocolo sem nenhum LLM

```bash
cd /mnt/c/ADINT/ADINT_AULA
/opt/adint-venv/bin/python3 fala_com_mcp.py MCP/mcp_1_ping.py ping
```

Imprime o `initialize`, o `tools/list` e o `tools/call` — as três mensagens que
o Claude trocaria. **É o melhor primeiro slide do bloco:** o aluno vê que o
servidor não sabe que existe IA do outro lado.

O degrau 2 é o que vale projetar sem argumento nenhum, só pelo `tools/list`:

```bash
/opt/adint-venv/bin/python3 fala_com_mcp.py MCP/mcp_2_argumento.py
```

```json
"description": "Faz ping num host...\n    Args:\n        host: IP ou dominio...",
"inputSchema": {"properties": {
    "host":    {"default": "8.8.8.8", "type": "string"},
    "pacotes": {"default": 3,         "type": "integer"}}}
```

A docstring virou a descrição. A anotação de tipo virou o schema.
**O modelo não lê o seu código — ele lê isso.** Documentação ruim aqui não é
desleixo, é bug: é com esse texto que o modelo decide se chama a ferramenta.

---

## Plugar no Claude

O formato do arquivo é **o mesmo** no Claude Desktop e no Claude Code: um objeto
`mcpServers`, e dentro de cada servidor um `command` e uma lista de `args`.
O que muda entre as três situações abaixo é **o que vai no `command`**.

| onde | arquivo | `command` |
|---|---|---|
| Claude Code (qualquer SO) | `.mcp.json` na raiz do projeto | ver abaixo |
| Claude Desktop no macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` | `python3` |
| Claude Desktop no Windows | `%APPDATA%\Claude\claude_desktop_config.json` | `wsl.exe` |

> **Onde está o seu `claude_desktop_config.json`:** o caminho acima é o padrão,
> mas instalações que guardam os dados fora do pacote usam
> `%LOCALAPPDATA%\Claude-Data\claude_<id>\claude_desktop_config.json`.
> O caminho certo é sempre o que abre em **Configurações → Desenvolvedor →
> Editar Config**.

> **Windows:** o servidor roda no WSL, então o `command` é `wsl.exe` e o
> caminho é o `/mnt/c/...`. Um caminho `C:\...` com `python3` do Windows **não**
> funciona: o `ping` do Windows tem outra sintaxe (`-n` em vez de `-c`).

### Claude Code no Windows, servidor no WSL

Copie `claude_mcp.json` para a raiz do projeto que você abre no Claude Code,
com o nome `.mcp.json`, e **ajuste duas coisas**:

- o nome da distro — `wsl -l -v` mostra o seu (aqui é `Ubuntu-24.04`);
- os caminhos `/mnt/c/ADINT/ADINT_AULA/MCP/...` — são **os meus**, troque pelos seus.

Ou, pela linha de comando, um por vez:

```bash
claude mcp add degrau1 -s project -- wsl.exe -d Ubuntu-24.04 -e \
  /opt/adint-venv/bin/python3 /mnt/c/ADINT/ADINT_AULA/MCP/mcp_1_ping.py
```

Depois, `/mcp` dentro do Claude Code: o servidor do `.mcp.json` aparece como
**⏸ pendente de aprovação** na primeira vez — você aprova e ele conecta.

### Claude Code no Linux, no Mac, ou rodando dentro do WSL

Sem `wsl.exe` no meio, e aí não há BOM nenhum:

```bash
claude mcp add degrau1 -s project -- /opt/adint-venv/bin/python3 \
  /caminho/para/ADINT_AULA/MCP/mcp_1_ping.py
```

### Claude Desktop no macOS

`claude_desktop_config_mac.json` é o modelo — troque `SEU_USUARIO` e o caminho,
e cole em `~/Library/Application Support/Claude/claude_desktop_config.json`.
Se o servidor não subir, troque `"python3"` pela saída de `which python3`: o
Claude Desktop lança o processo com um `PATH` mínimo e pode pegar outro Python,
sem o pacote `mcp` instalado.

### Como mostrar a progressão em aula

Deixe **um** degrau registrado por vez: o modelo vê poucas ferramentas e a
diferença entre os degraus fica limpa. Com os quatro registrados ao mesmo tempo
você mostra outra coisa — o modelo **escolhendo** entre ferramentas parecidas,
só pela descrição.

---

## O que pedir ao Claude em cada degrau

| degrau | peça isto | o que o aluno deve notar |
|---|---|---|
| 1 | *"faz um ping"* | o modelo não escolheu o alvo: está no código |
| 2 | *"faz 2 pings no 1.1.1.1"* | ele preencheu `host` e `pacotes` sozinho — leu o schema |
| 3 | *"a rede está boa?"* | com `ping_cru` ele interpreta texto; com `ping_analisado` a conclusão já vem pronta |
| 3 | *"usa a ferramenta crua"* | mesma coleta, duas saídas — compare o que ele escreve |
| 4 | *"diagnostica o 1.1.1.1 e me diz por quê"* | ele cita a faixa e a recomendação da KB |
| 4 | *"qual é o critério de latência alta?"* | ele chama `explica_kb` — o critério é auditável |

A pergunta que fecha o bloco: **"quem decidiu que 200 ms é ruim?"**
Não foi o `ping`, nem o modelo. Foi quem escreveu a KB. É isso que um agente é.

---

## Os três bytes que param a aula

Claude no Windows + servidor no WSL = `wsl.exe` no meio. E o `wsl.exe`
**injeta um BOM (`EF BB BF`) no primeiro byte do stdin**. Medido:

```powershell
@('{"a":1}','{"b":2}') | wsl.exe -d Ubuntu-24.04 -e od -An -tx1
#  ef bb bf 7b 22 61 22 3a 31 7d 0a 7b 22 62 22 3a 32 7d 0a
#  ^^^^^^^^ ninguém mandou isso
```

A primeira mensagem do MCP é o `initialize`, então é ela que chega suja:

```
Invalid JSON: expected value at line 1 column 1
Internal Server Error
```

O `tools/list` depois funciona — **só o handshake morre**, e no Claude isso
aparece como "servidor falhou", sem dizer por quê. Por isso cada degrau chama
`tira_bom()` antes do `mcp.run()`. Dentro do WSL não há BOM e a função não
consome nada.

É o **mesmo BOM** do arquivo de combo do bloco [9] (`BOM no inicio ... True`).
Ele volta sempre.

---

## O mesmo comando, dois sistemas, respostas diferentes

A primeira versão destes scripts usava `ping -c 3 -W 2`. No Linux o `-W` é
**segundos**; no macOS é **milissegundos**. O mesmo `-W 2` que espera 2 s no WSL
espera **2 ms** no Mac — e uma resposta normal de 8 ms vira **perda de pacote**.
O degrau 3 responderia *"host inalcançável / CRÍTICO"* para um host vivo.

E o resumo do `ping` também é diferente:

| | perda | tempos |
|---|---|---|
| Linux | `4 packets transmitted, 4 received, 0% packet loss` | `rtt min/avg/max/mdev` |
| macOS | `4 packets transmitted, 4 packets received, 0.0% packet loss` | `round-trip min/avg/max/stddev` |

A regex antiga era `(\d+)% packet loss`. Medido contra a saída dos dois:

```
Linux         regex ANTIGA -> 0        regex NOVA -> 0
macOS         regex ANTIGA -> 0        regex NOVA -> 0.0
macOS 12.5%   regex ANTIGA -> 5        regex NOVA -> 12.5
```

Em `12.5% packet loss` o `(\d+)` casava com o **`5`** do decimal. Perda de 12,5%
virava 5%, sem erro nenhum na tela. Por isso agora: sem `-W` (quem limita é o
`timeout=` do `subprocess`, igual nos dois) e `([\d.]+)` com `float()`.

> **A fala:** *"nenhum dos dois bugs dá exceção. Os dois dão uma resposta
> errada com cara de certa. É o pior tipo de defeito num agente — e ele entrou
> por uma flag de uma linha."*

## Toda tool é superfície de ataque

Do degrau 2 em diante o `host` vem **de fora** — quem digita é o modelo, a
partir do que alguém escreveu no chat. Daí o filtro:

```python
VALIDO = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.\-]{0,99}$')
```

Um `-f` no lugar do host vira `ping -f` (flood). A regra: trate argumento de
tool como entrada de usuário na web — porque é exatamente isso.

**E o filtro já esteve errado.** A primeira versão era
`^[A-Za-z0-9.\-]{1,100}$`: barrava `; rm -rf`, mas o hífen estava dentro da
classe e `-f` passava. Medido:

```
'8.8.8.8'                  ANTIGO: passa   NOVO: passa
'my-host.example.com'      ANTIGO: passa   NOVO: passa
'-f'                       ANTIGO: passa   NOVO: barra
'-i0.001'                  ANTIGO: passa   NOVO: barra
'--flood'                  ANTIGO: passa   NOVO: barra
'8.8.8.8; rm -rf /tmp/x'   ANTIGO: barra   NOVO: barra
```

Com a versão antiga, `{"host": "-f"}` devolvia
`ping: usage error: Destination address required` — a flag **chegou no
comando**; o que salvou foi o `ping` exigir um destino. Sorte, não defesa.
A correção é o primeiro caractere ter de ser letra ou número.

Os quatro degraus só fazem `ping` em um host. Nenhum lê arquivo, nenhum escreve,
nenhum fala com o Elastic. Isso é de propósito: é o piso da escada.
