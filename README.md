::: {align="center"}
`<img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>`{=html}
`<img src="https://img.shields.io/badge/Security-Email%20Analysis-8E24AA?style=for-the-badge"/>`{=html}
`<img src="https://img.shields.io/badge/Status-MVP%20Functional-00C853?style=for-the-badge"/>`{=html}

`<br/>`{=html}`<br/>`{=html}

# Email Fraud Shield

**Detecção de phishing e fraude em e-mails com análise heurística e
arquitetura modular**

*Analyze. Score. Explain.*
:::

------------------------------------------------------------------------

## O Problema

E-mails continuam sendo o principal vetor de ataque em engenharia
social.

  -----------------------------------------------------------------------
  Sintoma                             Impacto
  ----------------------------------- -----------------------------------
  Phishing cada vez mais sofisticado  Roubo de credenciais e acesso
                                      indevido

  Usuários não sabem identificar      Alto índice de cliques em links
  sinais de fraude                    maliciosos

  Ferramentas complexas são           Barreiras para aprendizado prático
  inacessíveis para estudo            em segurança

  Falta de explicabilidade nas        Difícil entender por que algo é
  decisões                            malicioso
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## A Solução

O **Email Fraud Shield** é um analisador de e-mails que aplica:

-   parsing estruturado de `.eml`
-   motor heurístico baseado em sinais reais de phishing
-   sistema de pontuação de risco
-   classificação final explicável
-   geração de relatório estruturado em JSON

> O objetivo não é substituir soluções corporativas, mas demonstrar
> **como sistemas de detecção de fraude funcionam na prática**.

------------------------------------------------------------------------

## Como Funciona

    .eml → Ingestão → Parser → Heurísticas → Score → Classificação → JSON Report

------------------------------------------------------------------------

## Funcionalidades

### Core

-   Leitura de arquivos `.eml` locais
-   Parser robusto de:
    -   cabeçalhos
    -   corpo (texto e HTML)
    -   links
    -   autenticação (SPF, DKIM, DMARC)
-   Tratamento defensivo de e-mails malformados

### Análise de Segurança

-   Motor heurístico com múltiplas regras
-   Detecção de:
    -   falhas de autenticação
    -   linguagem de urgência
    -   solicitação de dados sensíveis
    -   links suspeitos (HTTP)
    -   domínios potencialmente falsificados
    -   pressão por verificação de conta
-   Sistema de scoring acumulativo

### Classificação

-   `LEGITIMO`
-   `SUSPEITO`
-   `PHISHING_PROVAVEL`
-   `ALTO_RISCO`

### Output

-   Relatório JSON estruturado
-   CLI com execução parametrizável
-   Logs de execução

------------------------------------------------------------------------

## Como Executar

``` bash
git clone https://github.com/seu-usuario/email-fraud-shield.git
cd email-fraud-shield
pip install -r requirements.txt

python main.py
```

------------------------------------------------------------------------

## Limitações

-   Não analisa anexos binários
-   Não integra com inbox real (IMAP/API)
-   Não substitui soluções corporativas
-   Baseado em heurísticas simples (MVP)

------------------------------------------------------------------------

## Sobre o Desenvolvedor

Desenvolvido por **Jefferson Ferreira**
