import bcrypt
from datetime import datetime, timedelta, timezone # Importa timezone para lidar com fusos horários
from jose import JWTError, jwt # Biblioteca para trabalhar com JWTs (JSON Web Tokens)

# -- Configurações do JWT ---
# Chave secreta do sistema para assinar os tokens e garantir que não são falsos. Foi gerada aleatoriamente com o comando: openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256" # Algoritmo de assinatura do token.
ACCESS_TOKEN_EXPIRE_MINUTES = 30 # Tempo em minutos de expiração do token de acesso.


# --- Função para "hashar" a senha ---
def hash_password(password: str) -> str:
    # Recebe uma senha em texto puro e retorna um hash seguro
    pwd_bytes = password.encode('utf-8') # Transforma a senha em bytes
    
    salt = bcrypt.gensalt() # Gera um salt aleatório
    
    hashed_password = bcrypt.hashpw(pwd_bytes, salt) # Gera o hash

    return hashed_password.decode('utf-8') # Decodifica o hash (bytes) de volta para string pra salvar no banco


# --- Função para "verificar" a senha ---
def verify_password(plain_password: str, hashed_password: str) -> bool:
    # Recebe a senha em texto puro e o hash salvo no banco, retorna True se bater, False se não bater
    try:
        pwd_bytes = plain_password.encode('utf-8') # Transforma a senha em bytes
        
        hashed_bytes = hashed_password.encode('utf-8') # Transforma o hash salvo em bytes
        # O bcrypt.checkpw faz a mágica: Ele re-hasha a 'plain_password' usando o 'salt' que está embutido no 'hashed_password' e compara os resultados.
        
        return bcrypt.checkpw(pwd_bytes, hashed_bytes) # Verifica se a senha bate com o hash
    
    except Exception:
        # Se o hash for inválido ou algo der errado, nunca dê erro, apenas retorne False.
        return False
    

# --- Função para criar um token JWT ---
def create_access_token(data: dict) -> str: # Gera um token JWT em string com os dados fornecidos
    
    to_encode = data.copy() # Copia os dados para não alterar o original
    
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES) # Define o tempo de expiração do token com timezone UTC
    
    to_encode.update({"exp": expire}) # Adiciona o tempo de expiração aos dados a serem codificados
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM) # Gera o token JWT
    
    return encoded_jwt # Retorna o token gerado


# --- Função para verificar e decodificar um token JWT ---
def verify_access_token(token: str) -> dict | None:
    # Verifica o token JWT e retorna os dados decodificados se for válido, ou None se for inválido
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM]) # Verifica automaticamente se a assinatura (SECRET_KEY) e o prazo de validade (exp) são válidos
        
        return payload # Retorna os dados decodificados
    
    except JWTError:
        # Se o token for inválido, expirado ou algo der errado, a biblioteca 'jose' levanta um JWTError.e retorna None.
        return None