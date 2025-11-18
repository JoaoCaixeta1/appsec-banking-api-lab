from pydantic import BaseModel, EmailStr # Importa a classe base para modelos Pydantic e o tipo EmailStr para validação de emails

# -- Molde para criação de um usuário --
class UserCreate(BaseModel):
    username: str
    email: EmailStr # O Pydantic já verifica se é um email válido
    password: str
    nome: str
    cpf: str

# -- Molde para leitura de um usuário --
class User(BaseModel):
    id: int
    username: str
    email: EmailStr
    nome: str
    cpf: str
# Sem devolver o hash da senha (password) para o cliente em uma requisição, pois é sensível!

    class Config:
        from_attributes = True  # Permite converter de ORM (modelos SQLAlchemy) para Pydantic

# -- Molde para o token de acesso --
class Token(BaseModel):
    access_token: str
    token_type: str