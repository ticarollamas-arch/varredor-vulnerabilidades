#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Varredor Inteligente de Vulnerabilidades — triagem estática de fluxos de entrada perigosos.
Foca em entrada não confiável (req/argv/query) que chega a um sink perigoso.

Uso:
    python3 scanner.py [pasta]          # varre a pasta (padrão: diretório atual)
    python3 scanner.py --test           # roda o autoteste embutido
"""

import os
import re
import sys
from pathlib import Path

EXTENSOES = (".ts", ".tsx", ".js", ".jsx", ".go", ".py", ".java", ".env", ".json")

# Cada padrão: (rótulo, regex). Sink perigoso combinado com fonte de entrada.
PADROES = [
    (
        "CWE-78 | OS Command Injection",
        re.compile(
            r"""\b(exec|spawn|system|execSync|spawnSync|popen|subprocess\.(?:run|call|Popen))\s*\("""
            r"""[^)]*(?:["'][^"']*["']\s*\+|\$\{|\b\w*(?:input|args|argv|query|req|params|cmd|command)\b)""",
            re.IGNORECASE,
        ),
    ),
    (
        "CWE-22 | Path Traversal",
        re.compile(
            r"""\b(fs\.readFileSync|fs\.readFile|readFileSync|res\.sendFile|sendFile|open)\s*\("""
            r"""[^)]*\b(req|params|query|input|args|filename|filepath|path)\b""",
            re.IGNORECASE,
        ),
    ),
    (
        "CWE-522 | Segredo exposto em log",
        re.compile(
            r"""(console\.log|print|fmt\.Print\w*)\s*\([^)]*\b(secret|token|password|passwd|api_?key|private_?key)\b""",
            re.IGNORECASE,
        ),
    ),
    (
        "CWE-798 | Credencial hardcoded",
        re.compile(
            r"""\b(secret|api_?key|password|passwd|token|credential|senha|chave|segredo)\b\s*[:=]\s*["']([A-Za-z0-9_\-!@#$%^&*()]{10,})["']""",
            re.IGNORECASE,
        ),
    ),
]

IGNORAR = {"node_modules", "test", "tests", "example", "examples", "docs", "doc",
           "fixtures", ".git", ".github", "dist", "build", "__pycache__", "venv"}


def eh_falso_positivo(linha: str) -> bool:
    """Filtra ruído: comentário, texto de ajuda/uso e caminhos estáticos seguros."""
    s = linha.strip()
    low = s.lower()
    if s.startswith(("//", "*", "#")):
        return True
    if "help" in low or "usage" in low or "example:" in low or "--help" in low:
        return True
    if "path.join(__dirname" in linha or "path.join(process.cwd()" in linha:
        return True
    return False


def varrer(pasta: str):
    base = Path(pasta)
    if not base.exists():
        print(f"ERRO: pasta não existe: {pasta}")
        return 2

    total_arquivos = 0
    achados = []

    for raiz, dirs, arquivos in os.walk(base):
        dirs[:] = [d for d in dirs if d not in IGNORAR]
        for nome in arquivos:
            if not nome.endswith(EXTENSOES):
                continue
            fp = Path(raiz) / nome
            try:
                rel = fp.relative_to(base)
            except ValueError:
                rel = fp
            total_arquivos += 1
            try:
                linhas = fp.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            for n, linha in enumerate(linhas, 1):
                if len(linha) > 1000:
                    continue
                for rotulo, rx in PADROES:
                    if rx.search(linha) and not eh_falso_positivo(linha):
                        achados.append((rotulo, str(rel), n, linha.strip()[:120]))

    print("=" * 66)
    print("VARREDOR INTELIGENTE DE VULNERABILIDADES")
    print(f"Pasta: {base.resolve()}")
    print("=" * 66)
    for rotulo, arq, n, trecho in achados:
        print(f"\n[{rotulo}]")
        print(f"  arquivo: {arq}:{n}")
        print(f"  linha:   {trecho}")

    contagem = {}
    for rotulo, *_ in achados:
        cwe = rotulo.split("|")[0].strip()
        contagem[cwe] = contagem.get(cwe, 0) + 1

    print("\n" + "=" * 66)
    print("RESUMO")
    print(f"  arquivos analisados: {total_arquivos}")
    print(f"  pontos de atenção:   {len(achados)}")
    for cwe, q in sorted(contagem.items()):
        print(f"    {cwe} -> {q}")
    print("=" * 66)
    print("\nEstes achados são indícios de análise estática. Confirme manualmente "
          "antes de qualquer report — não constituem prova de exploração.")
    return 1 if achados else 0


def autoteste():
    print("Executando autoteste do scanner...")
    vulneravel = [
        "exec(req.query.cmd + ' arg');",
        'const senha = "super_secret_token_abc123xyz";',
        "data = fs.readFileSync(req.query.path);",
        "res.send(req.params.input);",
    ]
    seguro = [
        "// exemplo: use --help para ver os comandos",
        "const p = path.join(__dirname, 'public', file);",
        'console.log("Usage: scanner <pasta>");',
    ]
    pegou = sum(
        1 for linha in vulneravel
        for _, rx in PADROES if rx.search(linha) and not eh_falso_positivo(linha)
    )
    falso = any(
        rx.search(linha) and not eh_falso_positivo(linha)
        for linha in seguro for _, rx in PADROES
    )
    ok_vuln = pegou >= 3
    ok_falso = not falso
    print(f"  código vulnerável detectado: {'OK' if ok_vuln else 'FALHOU'} ({pegou} achados)")
    print(f"  código seguro ignorado:      {'OK' if ok_falso else 'FALHOU'}")
    return 0 if (ok_vuln and ok_falso) else 1


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--test" in argv:
        return autoteste()
    pasta = next((a for a in argv if not a.startswith("-")), ".")
    return varrer(pasta)


if __name__ == "__main__":
    sys.exit(main())
