FROM python:3.12-slim

LABEL org.opencontainers.image.title="Varredor Inteligente de Vulnerabilidades" \
      org.opencontainers.image.description="Triagem estática de fluxos de entrada perigosos (CWE-22/78/522/798)" \
      org.opencontainers.image.authors="Ana Caroline Lamas"

WORKDIR /app
COPY scanner.py /app/scanner.py

# Roda o autoteste durante o build: se o motor regredir, a imagem não é criada.
RUN python3 scanner.py --test

# A pasta a ser analisada é montada aqui em tempo de execução.
WORKDIR /code
ENTRYPOINT ["python3", "/app/scanner.py"]
CMD ["/code"]
