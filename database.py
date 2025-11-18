from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Os mesmos dados do docker-compose.yml
DATABASE_URL = "postgresql://appsec_user:super-secure-password-123@127.0.0.1:5432/appsec_banking-db"

#O create_engine cria a conexão com o banco de dados
engine = create_engine(DATABASE_URL)

# O sessionmaker cria uma "fábrica" de sessões para interagir com o banco de dados
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

#Todas as tabelas serão herdadas desta classe, assim o SQLAlchemy sabe quais tabelas criar e mapear
Base = declarative_base()