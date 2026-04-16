::: {align="center"}
`<img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>`{=html}
`<img src="https://img.shields.io/badge/Security-Email%20Fraud%20Detection-8E24AA?style=for-the-badge"/>`{=html}
`<img src="https://img.shields.io/badge/Status-MVP%20Complete-00C853?style=for-the-badge"/>`{=html}

`<br/>`{=html}`<br/>`{=html}

# Email Fraud Shield

**Detecção de phishing e fraude em e-mails com análise heurística e
explicável**

*Analyze. Score. Explain.*
:::

------------------------------------------------------------------------

## O Problema

E-mails continuam sendo o principal vetor de ataques de engenharia
social.

  -----------------------------------------------------------------------
  Sintoma                             Impacto
  ----------------------------------- -----------------------------------
  Phishing cada vez mais sofisticado  Roubo de credenciais e acesso
                                      indevido

  Golpes financeiros via e-mail (BEC) Transferências indevidas e fraude
                                      corporativa

  Usuários não reconhecem sinais de   Alto índice de comprometimento
  risco                               

  Ferramentas reais são caixas-pretas Falta de explicabilidade
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## A Solução

O **Email Fraud Shield** é um analisador de e-mails que simula, de forma
prática, como sistemas de detecção de fraude funcionam.

Ele aplica:

-   parsing estruturado de `.eml`
-   motor heurístico baseado em sinais reais de ataque
-   sistema de pontuação de risco
-   classificação final explicável
-   geração de relatório estruturado em JSON

> O foco não é substituir soluções corporativas, mas demonstrar **como a
> lógica de detecção funciona na prática**.

------------------------------------------------------------------------

## Como Funciona

    .eml → Ingestão → Parser → Heurísticas → Score → Classificação → JSON Report

------------------------------------------------------------------------

## Dataset de Validação

O sistema foi testado com um conjunto de 8 e-mails simulando cenários
reais.

------------------------------------------------------------------------

## Resultado do Motor

ALTO_RISCO=2\
PHISHING_PROVAVEL=3\
SUSPEITO=1\
LEGITIMO=2

------------------------------------------------------------------------

## Sobre o Desenvolvedor

Desenvolvido por Jefferson Ferreira
