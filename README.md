# appsec-banking-api-lab

## Objetivo do Projeto

Este repositório é um **Laboratório de DevSecOps Prático** focado no ciclo **Build-Break-Fix** (Construir-Quebrar-Corrigir). A aplicação simula um serviço bancário básico e foi intencionalmente construída para ser vulnerável a ataques de **Autorização**.

O objetivo final é demonstrar a capacidade de:
1.  Identificar o risco (Ataque).
2.  Implementar a correção (Defesa).
3.  Verificar o código contra padrões de mercado (Verificação).

---

## Tecnologias Utilizadas

| Componente | Tecnologia | Finalidade |
| :--- | :--- | :--- |
| **API** | Python 3.x, FastAPI | Desenvolvimento rápido e assíncrono. |
| **Servidor** | Uvicorn | Servidor ASGI de alto desempenho. |
| **Banco de Dados** | PostgreSQL (via Docker) | Persistência de dados (essencial para testar SQL Injection). |
| **Autenticação** | JWT (JSON Web Tokens) e Bcrypt | Gerenciamento de tokens e hashing de senha (OWASP C3). |

---

## Vulnerabilidade Explorada: IDOR (A01: Broken Access Control)

### 1. O Risco (OWASP Top 10)

O principal foco da quebra foi a falha de **Broken Access Control (Controle de Acesso Quebrado)**, classificada como **A01** (1º lugar) no **OWASP Top 10 2021**.

O ataque específico explorado é o **IDOR (Insecure Direct Object Reference)**.

### 2. A Falha no Código

A função `GET /profile/{user_id}` exigia a **Autenticação** (o usuário precisava estar logado, via `current_user = Depends(...)`), mas **falhava em implementar a Autorização**.

* A **linha vulnerável** confiava cegamente no parâmetro `user_id` vindo da URL.
* **Exploit:** Usuário logado como João (ID 1) conseguia acessar o perfil de Maria (ID 2) ao alterar o ID na rota, vazando dados sensíveis.

### 3. As CWEs Relacionadas

As vulnerabilidades de IDOR/Broken Access Control são diretamente mapeadas para as seguintes enumerações de fraquezas comuns:

* **CWE-639:** Authorization Bypass Through User-Controlled Key (A mais direta)
* **CWE-285:** Improper Authorization (Falha geral na checagem)
* **CWE-200:** Exposure of Sensitive Information to an Unauthorized Actor

---

## O Ciclo de Defesa

O projeto está atualmente na versão **corrigida**. A defesa foi implementada através da checagem de **Autorização** explícita:

1.  **Defesa (Proactive Control):** Foi aplicado o **OWASP Proactive Control C4: Implement Access Control**, adicionando uma estrutura condicional (`if current_user.id != user_id: raise HTTPException(403)`) na função `get_user_profile`.
2.  **Verificação (ASVS):** A implementação dessa checagem garante que o código satisfaz requisitos críticos da seção **V4: Access Control** do **OWASP ASVS** (Application Security Verification Standard).

---

## Como Rodar o Laboratório (Modo Exploit)

Para testar o ciclo completo na sua máquina, siga estas etapas.

### Pré-requisitos
* Python 3.x e `venv` (ambiente virtual).
* Docker Desktop rodando.

### 1. Setup e Instalação
```bash
# Clone o repositório
git clone [seu_link_aqui]
cd appsec-banking-api-lab
# Crie e ative o ambiente virtual
python3 -m venv venv
source venv/bin/activate
# Instale as dependências
pip3 install -r requirements.txt
