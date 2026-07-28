# Lua/Roblox Obfuscation Detector

Detector/classificador de obfuscadores usados em scripts Lua/Luau (Roblox).
Mostra **um único veredito** (o de maior confiança) por padrão. Não desofusca,
não remove proteções e não contém rotina de obfuscação real de nenhuma
ferramenta listada — só reconhece padrões públicos/estruturais que cada uma
costuma deixar no código de saída.

## Arquivos

- `lua_obf_detector.py` — motor de detecção (CLI).
- `lua_obf_detector_gui.py` — interface gráfica (Tkinter) para selecionar um
  arquivo/pasta e ver o resultado sem usar terminal.
- `signatures.json` — base de assinaturas. Edite este arquivo pra
  adicionar/ajustar detectores sem tocar no código Python.

## Uso — Interface gráfica

```bash
python3 lua_obf_detector_gui.py
```

Abre uma janela com botões "Selecionar arquivo..." / "Selecionar pasta...",
checkboxes pra mostrar evidências e/ou ranking completo, e uma área de texto
com o resultado.

## Uso — Linha de comando

```bash
python3 lua_obf_detector.py script.lua                # só o veredito
python3 lua_obf_detector.py script.lua --evidence      # veredito + motivos
python3 lua_obf_detector.py pasta/ --json              # lote, saída JSON
python3 lua_obf_detector.py script.lua --all           # ranking completo (todos os candidatos)
python3 lua_obf_detector.py script.lua --rules outro.json  # usar outra base de assinaturas
```

## Obfuscadores cobertos

| Ferramenta | Confiança das assinaturas |
|---|---|
| Prometheus | Alta — baseada no código-fonte real (v0.2.11.1) |
| Hercules Obfuscator | Alta — baseada no código-fonte real (repo oficial) |
| 25ms | Alta — baseada em amostra real |
| MoonVeil | Alta — baseada em amostra real |
| Goofyscator | Alta — baseada em amostra real |
| LuaSyntax | Alta — baseada em amostra real |
| WynFuscate | Alta — baseada em amostra real |
| Luraph | Alta — cobre várias versões (v11 até v14.8+), baseada em várias amostras reais |
| MoonSec V2/V3 | Média — heurística pública conhecida |
| IronBrew 1/2 | Média — heurística pública conhecida |
| WeAreDevs | Média — heurística pública conhecida |
| IronVeil | Baixa/média — sem amostra real confirmada ainda |
| LuaObfuscator.com | Baixa/média — sem amostra real confirmada ainda |
| 69ms | Baixa — sem amostra real confirmada ainda |
| Base64 / XOR / Hex | Técnicas genéricas (fallback, tier 2) |

## Análise avançada (`--advanced` / checkbox na GUI)

Opcional, aditiva, não muda o veredito padrão nem o tempo de análise quando
desligada. Quando ligada, adiciona ao final do relatório:

- **Fingerprint estrutural**: funções, closures, tabelas, strings, números,
  operadores, profundidade de blocos, identificadores (média/maior/únicos),
  densidades por KB, estatísticas de linha, comentários, e contagem de uso de
  ~25 APIs/palavras-chave (goto, getfenv, loadstring, bit32, etc).
- **Scores 0-100 por categoria**: Virtual Machine, String Encryption, Number
  Encoding, Control Flow Flattening, Constant Encryption, Bytecode,
  Compression, Anti Debug, Anti Tamper, Loader, Environment Spoof, Dynamic
  Execution, Encoding, Dead/Junk Code — cada um com a lista de evidências que
  formaram o score.
- **Técnicas específicas**: Base64/32/58/85, escapes hex/octal/decimal/unicode,
  literais hex/binários, XOR, indícios de RC4 (loop 0-255), TEA/XXTEA
  (constante delta 0x9E3779B9), AES (S-box), magic bytes de gzip/zlib.
- **Cadeia provável de camadas**: as técnicas detectadas, ordenadas pela
  posição da primeira ocorrência no arquivo.
- **Família provável sem watermark**: ranking de confiança estrutural (sem
  contar nenhum watermark) das ferramentas tier 1 — útil quando o watermark
  foi removido ou é de outra ferramenta.

Implementado num arquivo separado (`advanced_analysis.py`), tokenizando o
arquivo **uma única vez** (regex compilada uma vez, no import do módulo) e
derivando tudo daquela lista de tokens — sem re-ler o arquivo várias vezes.
Em teste com um arquivo de ~1.1MB, a análise avançada levou ~4s; o modo padrão
(sem `--advanced`) continua na casa de milissegundos, sem nenhuma mudança de
comportamento ou velocidade.

### O que ficou de fora (e por quê)

Pra não pesar o detector nem arriscar falsos positivos, algumas coisas do
pedido original foram **propositalmente simplificadas ou não implementadas**:

- **Parsing real de AST**: não foi feito. Obfuscadores usam dialetos/sintaxes
  não-padrão com frequência (crases como delimitador de string, literais numéricos
  com underscore, floats em hex, etc — vimos isso nas próprias amostras que você
  mandou). Um parser rígido de Lua quebraria constantemente. Em vez disso, uso
  um tokenizer tolerante + regex, que lida bem com essas variações.
- **Dead code / Junk code**: sem análise real de alcançabilidade e escopo (que
  exigiria um parser completo + resolução de variáveis), é impossível ter
  certeza se um bloco é "morto" de verdade. O score dessa categoria é
  propositalmente conservador e deve ser lido como indício fraco, não prova.
- **RC4 / AES / TEA / XXTEA**: detectados só por constantes/estruturas públicas
  e bem conhecidas do algoritmo (S-box da AES, delta 0x9E3779B9 da TEA, loop
  de 256 do RC4). Se o obfuscador calcular essas constantes em runtime em vez
  de deixá-las literais, não detectamos — isso é intencional, pra não arriscar
  falso positivo tentando "adivinhar" uma cifra.
- **LZW / LZ4 / Huffman**: essas compressões não têm magic bytes universais
  (diferente de gzip/zlib), então o sinal pra elas é só menção de nome no
  código — fraco por natureza, já que nomes costumam ser renomeados pelo
  obfuscador. Documentei isso explicitamente na saída.
- **Cadeia de camadas como fluxo de dados real**: mostrar "Base64 → XOR → VM"
  como uma cadeia de dataflow *verificada* exigiria de fato interpretar/rodar
  o script — isso é execução, não análise estática, e foge do escopo de um
  detector. O que entrego é a ordem de primeira aparição no texto, deixado
  claro como heurística posicional, não prova de encadeamento real.

## Novos obfuscadores adicionados nesta rodada

- **LuaSyntax** — watermark literal + tabela de lookup alfabeto→índice
  construída a partir de uma string de charset customizado + chamadas de
  método via `string["by".."te"](...)` (nomes da lib padrão partidos e
  concatenados).
- **WynFuscate** — watermark literal + domínio `getpolsec.com` + loop de hash
  polinomial (base 131, mod 2147483647) pra resolver globais sem nomes
  literais + cadeia `(_ENV or _G)` repetida.
- **Luraph**: cobertura ampliada pra v14.8 (números com underscore em
  posições variadas: `0x__B`, `0X15a__`) e v13.6.7 (estilo antigo de wrapper
  com parâmetros e hex float `0x1.43B13ecp28`) — ambas já caem no detector
  Luraph existente via watermark, sem precisar de assinatura nova.

Se você tiver amostras reais de IronVeil, LuaObfuscator.com ou 69ms, me manda
que eu refino essas assinaturas do mesmo jeito que fiz com as outras.

### Sobre o Luraph

O Luraph mudou bastante de formato entre versões. O detector cobre dois
estilos conhecidos:
- **v14.x recente**: `return({A=function(...) ... end, B=function(...) ... end})`
  — tabela de closures nomeadas com chaves curtas.
- **v11 a v14.3**: `return(function(H,fW,y,q,...) ... while true do ... end)(...)`
  — uma única função com dezenas de parâmetros de 1-2 letras e dispatch
  numérico via `while true do`.

Ambos os estilos, mais o watermark literal (`generated/protected using Luraph`,
`lura.ph`) e as diretivas de pragma (`LPH_JIT`, `LPH_NO_VIRTUALIZE`, etc.),
alimentam o mesmo detector — então novas versões que reutilizem qualquer um
desses elementos continuam sendo pegas.

## Detecção de conflito watermark vs. estrutura (importante)

Um watermark (comentário tipo `-- Obfuscated by X`) é só texto — é trivial editar,
apagar ou copiar de outro arquivo. Por isso o detector NÃO confia cegamente nele:

1. Cada ferramenta acumula uma **confiança estrutural** separada (baseada só nos
   checks que não são watermark — VM, funções de decode, padrões de loop, etc).
2. Se o watermark aponta pra ferramenta A, mas a ferramenta B bate muito mais forte
   na estrutura real do código (confiança estrutural de B ≥ 35% e pelo menos
   20 pontos percentuais acima de A, com no mínimo 2 evidências estruturais
   distintas), o veredito final vira B — com uma nota `[CONFLITO]` explicando o
   porquê e uma confiança mais conservadora (50-75%, não os 85-99% de um watermark
   limpo).
3. Isso cobre tanto watermark editado manualmente quanto obfuscadores que
   reaproveitam/fazem rebrand da saída de outro (como o caso MoonVeil/Luraph que
   apareceu durante os testes).

Ferramentas com pouquíssimos checks estruturais próprios (25ms, 69ms) não entram
nessa disputa de conflito — exigimos um mínimo de robustez estrutural (`structural_max
>= 40` e pelo menos 2 acertos) pra evitar falso-positivo de conflito contra
heurísticas fracas tipo "arquivo curto e denso".

## Identificação de versão

Prometheus, Hercules, Luraph, Goofyscator e MoonVeil têm um `version_pattern`
(regex com grupo de captura) no `signatures.json`. Quando o watermark contém um
número de versão, ele aparece no veredito: `Luraph (v14.4.2)`, `Hercules Obfuscator
(v2.0.0)`, etc. Fácil de adicionar `version_pattern` pra qualquer outra ferramenta
nova que você incluir.

## Como adicionar/ajustar uma assinatura

Edite `signatures.json`. Cada ferramenta tem uma lista de `checks`. Tipos suportados:

- `regex`: 1 padrão, conta ocorrências, pontua se `min_count` for atingido.
- `regex_all`: vários padrões, todos precisam bater (E lógico).
- `long_lines`: conta linhas maiores que `threshold` caracteres.
- `short_high_entropy`: arquivo com poucas linhas (`max_lines`) e entropia alta (`min_entropy`).

Marque `"explicit": true` em checks que são watermarks/nomes literais — eles
praticamente garantem o veredito sozinhos (85-99% de confiança).

`"tier": 1` = ferramenta nomeada. `"tier": 2` = técnica genérica (só vence se
nenhuma ferramenta de tier 1 bater com confiança razoável).
