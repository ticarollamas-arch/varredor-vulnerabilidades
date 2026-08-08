# Varredor Inteligente de Vulnerabilidades

Triagem estática de código que aponta onde entrada não confiável (`req`, `query`, `argv`) chega a uma função perigosa. Cobre path traversal, injeção de comando, segredo em log e credencial hardcoded — em JS/TS, Python, Go e Java.

![Python](https://img.shields.io/badge/python-3.12-blue)
![Docker](https://img.shields.io/badge/docker-pronto-blue)
![Licença](https://img.shields.io/badge/licen%C3%A7a-MIT-green)

> Ferramenta de **triagem**: ela sublinha pontos suspeitos para você revisar, não prova exploração. Confirme cada achado manualmente antes de qualquer report.

## Uso rápido com Docker

```bash
git clone https://github.com/ticarollamas-arch/varredor-vulnerabilidades
cd varredor-vulnerabilidades
docker build -t varredor .
```

O `docker build` roda o autoteste embutido — se ele falhar, a imagem nem é criada.

Para analisar **qualquer projeto**, monte a pasta dele em `/code`:

```bash
docker run --rm -v /caminho/do/projeto:/code varredor
```

No Termux/Android, a pasta atual:

```bash
docker run --rm -v "$PWD":/code varredor
```

## Sem Docker (Python direto)

```bash
python3 scanner.py /caminho/do/projeto
python3 scanner.py --test      # autoteste
```

## O que detecta

| CWE | Risco | Como casa |
|---|---|---|
| CWE-22 | Path Traversal | entrada até `readFile/sendFile/open` |
| CWE-78 | OS Command Injection | entrada até `exec/spawn/system/subprocess` |
| CWE-522 | Segredo exposto em log | `secret/token/senha` dentro de `console.log/print` |
| CWE-798 | Credencial hardcoded | `senha/api_key/token = "…"` (PT e EN) |

## Filtro de falso positivo

Antes de reportar um achado, o scanner descarta:
- comentários e linhas de ajuda (`--help`, `usage`, `example:`);
- caminhos estáticos seguros (`path.join(__dirname, …)`, `process.cwd()`).

## Limitações

- Casamento por linha: fonte e sink precisam estar na mesma linha (não segue variável entre linhas).
- Regex, não AST: código muito ofuscado ou dinâmico escapa.
- É triagem — reduz o que chega à revisão manual, não substitui.

## Licença

MIT
