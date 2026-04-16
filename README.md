<div align="center">

<img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/Security-Email%20Fraud%20Detection-8E24AA?style=for-the-badge"/>
<img src="https://img.shields.io/badge/Status-MVP%20Complete-00C853?style=for-the-badge"/>

<br/><br/>

# Email Fraud Shield

**Detecção de phishing e fraude em e-mails com análise heurística e explicável**

*Analyze. Score. Explain.*

</div>

---

## O Problema

E-mails continuam sendo o principal vetor de ataques de engenharia social.

| Sintoma | Impacto |
|---|---|
| Phishing cada vez mais sofisticado | Roubo de credenciais e acesso indevido |
| Golpes financeiros via e-mail (BEC) | Transferências indevidas e fraude corporativa |
| Usuários não reconhecem sinais de risco | Alto índice de comprometimento |
| Ferramentas reais são caixas-pretas | Falta de explicabilidade |

---

## A Solução

O **Email Fraud Shield** é um analisador de e-mails que simula, de forma prática, como sistemas de detecção de fraude funcionam.

Ele aplica:

- parsing estruturado de `.eml`
- motor heurístico baseado em sinais reais de ataque
- sistema de pontuação de risco
- classificação final explicável
- geração de relatório estruturado em JSON

> O foco não é substituir soluções corporativas, mas demonstrar **como a lógica de detecção funciona na prática**.

---

## Como Funciona

```text
.eml → Ingestão → Parser → Heurísticas → Score → Classificação → JSON Report
```

Pipeline determinística com análise baseada em evidências.

---

## Funcionalidades

### Core
- Leitura de arquivos `.eml`
- Parser robusto de:
  - cabeçalhos
  - corpo (texto e HTML)
  - links
  - autenticação (SPF, DKIM, DMARC)
- Tratamento de e-mails malformados

### Motor de Análise
- Regras heurísticas com scoring acumulativo
- Detecção de múltiplos vetores:
  - phishing clássico
  - engenharia social
  - BEC (Business Email Compromise)
  - scams financeiros
  - links mascarados

### Classificação
- `LEGITIMO`
- `SUSPEITO`
- `PHISHING_PROVAVEL`
- `ALTO_RISCO`

### Output
- CLI com parâmetros
- Relatório JSON estruturado
- Logs de execução

---

## Dataset de Validação

O sistema foi testado com um conjunto de 8 e-mails simulando cenários reais:

| Tipo | Arquivo |
|---|---|
| Legítimo | `legit_newsletter.eml` |
| Legítimo (segurança) | `legit_password_reset.eml` |
| Phishing bancário | `phishing_bank_alert.eml` |
| Phishing entrega | `fake_delivery_notice.eml` |
| Conta suspeita | `suspicious_account_check.eml` |
| BEC (fraude corporativa) | `bec_payment_request.eml` |
| Scam cripto | `crypto_scam.eml` |
| Link mascarado | `masked_link_attack.eml` |

---

## Resultado do Motor

Execução real do sistema:

```text
Summary: ALTO_RISCO=2, LEGITIMO=2, PHISHING_PROVAVEL=3, SUSPEITO=1
Total loaded: 8
Total failed: 0
```

### Exemplos

| Cenário | Score | Classification |
|---|---:|---|
| Phishing bancário | 115 | `ALTO_RISCO` |
| Scam financeiro | 65 | `PHISHING_PROVAVEL` |
| BEC (fraude corporativa) | 42 | `SUSPEITO` |
| Legítimo | 0 | `LEGITIMO` |

### Heurísticas Implementadas (v2)

| Categoria | Regras |
|---|---|
| Autenticação | `authentication_failures` |
| Engenharia Social | `urgency_language`, `account_blocking_or_forced_verification`, `sensitive_information_request` |
| Fraude Financeira | `financial_request_language`, `unrealistic_promise` |
| Links | `suspicious_links`, `mismatched_link_text` |
| Identidade | `suspicious_sender_patterns` |

---

## Arquitetura

```text
┌──────────────────────────────────────────────┐
│  CLI Layer        argparse                   │
├──────────────────────────────────────────────┤
│  Core Pipeline    Ingestor + Parser          │
├──────────────────────────────────────────────┤
│  Analyzer         Heuristics + Scoring       │
├──────────────────────────────────────────────┤
│  Classification   Risk thresholds            │
├──────────────────────────────────────────────┤
│  Reporting        JSON output                │
└──────────────────────────────────────────────┘
```

### Decisões Técnicas

**Heurísticas primeiro**  
Sistema determinístico e explicável, sem dependência de IA para a decisão principal.

**Arquitetura modular**  
Cada camada isola uma responsabilidade: ingestão, parsing, análise, classificação e reporting.

**Explicabilidade**  
Cada classificação é acompanhada por regras acionadas, severidade e pontuação acumulada.

---

## Estrutura do Projeto

```text
email_fraud_shield/
├── app/
│   ├── alerts/
│   ├── analyzer/
│   │   ├── classifier.py
│   │   ├── heuristics.py
│   │   └── scorer.py
│   ├── ingestor/
│   │   └── email_ingestor.py
│   ├── llm/
│   ├── models/
│   │   └── email_models.py
│   ├── parser/
│   │   └── email_parser.py
│   └── reporting/
│       └── report_generator.py
├── data/
│   ├── samples/
│   └── output/
├── main.py
├── config.py
└── requirements.txt
```

---

## Como Executar

**Pré-requisitos:** Python `3.10+`

```bash
git clone https://github.com/jeffersonferreira-ti/email_fraud_shield.git
cd email_fraud_shield
pip install -r requirements.txt

python main.py --source ./data/samples --output ./data/output/report.json --summary
```

---

## Limitações

- Não analisa anexos binários
- Não integra com inbox real (IMAP/API)
- Não substitui soluções corporativas
- Baseado em heurísticas determinísticas (MVP)

---

## Roadmap

| Versão | Foco | Status |
|---|---|---|
| v1.0 | MVP heurístico + CLI | ✅ Concluído |
| v1.1 | Dataset expandido + heurísticas v2 | ✅ Concluído |
| v1.2 | Refinamento (delivery scams, brand impersonation) | 🔄 Planejado |
| v2.0 | Integração com LLM (análise complementar) | 📋 Planejado |
| v2.1 | Integração com inbox real | 💡 Futuro |

---

## Sobre o Projeto

Projeto desenvolvido como estudo prático de:

- Segurança da Informação
- Detecção de fraudes
- Engenharia de software
- Arquitetura modular

---

## Sobre o Desenvolvedor

Desenvolvido por **Jefferson Ferreira**.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=flat&logo=linkedin)](https://www.linkedin.com/in/jefferson-ferreira-ti/)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=flat&logo=github)](https://github.com/jeffersonferreira-ti)

---

<div align="center">
<sub>Email Fraud Shield · 2026</sub>
</div>
