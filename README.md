# appsec-banking-api-lab

Essa é uma aplicação propositalmente vulnerável (A01: IDOR), onde é permitido que um usuário veja o perfil de outros, sem autorização. Usando o próprio token de autenticação, é possível validar para acessar outros perfis que não exigem autenticação de tokens particulares.
    Ela exige a autenticação do usuário (current_user = Depends...), mas não verifica se o 'current_user' logado é o mesmo user_id da URL. Ela confia cegamente no user_id que vem da URL.

O IDOR (Insecure Direct Object Reference) saiu de 15º lugar da categoria de vulnerabilidades em Aplicações Web mais críticas, para 1º lugar em 2021.

Entre as CWEs (Common Weakness Enumerations) estão a CWE-200: Exposure of Sensitive Information to an Unauthorized Actor, CWE-201: Insertion of Sensitive Information Into Sent Data, and CWE-352: Cross-Site Request Forgery.

No código, para corrigir essa vulnerabilidade crítica, basta acessar a função def get_user_profile no arquivo main.py e implementar uma estrutura condicional para checagem de autorização.