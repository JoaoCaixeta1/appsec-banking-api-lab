from sqlalchemy import Column, Integer, String
from database import Base #importando a Base do database.py

#classe Modelo, onde o SQLAlchemy vai ler essa classe e traduzir para uma tabela SQL
class User(Base):
    __tablename__ = "users" #nome da tabela no banco de dados

    # --- Estas são as colunas da tabela ---
    id = Column(Integer, primary_key=True, index=True) # Chave primária, número inteiro, auto-gerado
    username = Column(String, unique=True, index=True) # Texto (String), único (não pode ter 2 e indexado (para buscas rápidas)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    nome = Column(String)
    cpf = Column(String, unique=True)

