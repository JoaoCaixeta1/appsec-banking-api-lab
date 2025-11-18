from fastapi import FastAPI, Depends, HTTPException, status # Importa FastAPI e dependências
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer # Entende formulários de autenticação e o Bearer serve para proteger rotas
from typing import Optional # Serve para tipos opcionais 
from database import engine, SessionLocal # Para conectar com o banco de dados
from sqlalchemy.orm import Session # Para criar sessões de banco de dados
from sqlalchemy.exc import IntegrityError # Para tratar erros de integridade (ex: duplicidade de chave única)

import schemas
import security
import models

models.Base.metadata.create_all(bind=engine) # Linha que "constrói" a tabela.

app = FastAPI(title="AppSec Banking API") # Cria a aplicação FastAPI
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login") # Ele sabe que deve procurar o token na URL /login.

def get_db(): # Função geradora para obter uma sessão de banco de dados
    db = SessionLocal() # Cria uma nova sessão (conexão)
    try:
        yield db # Fornece a sessão para o endpoint
    finally:
        db.close() # Garante que a sessão será fechada após o uso

def get_user_by_username(db: Session, username: str): # Busca um usuário pelo nome de usuário
    return db.query(models.User).filter(models.User.username == username).first()


def get_current_user(
    db: Session = Depends(get_db), 
    token: str = Depends(oauth2_scheme)
) -> models.User:
    # Pega o token do oauth2_scheme e o verifica, retornando o usuário do db
    
    # Verifica o token 
    payload = security.verify_access_token(token)
    
    if payload is None:
        # Se o token for inválido (expirado, assinatura errada)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    # 2. Token é válido! Descobre quem é o "dono" (o 'sub')
    username: str = payload.get("sub")
    if username is None:
        # Se o crachá não tiver um "dono"
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido (sem 'sub')",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    # 3. Busca o usuário no banco
    user = get_user_by_username(db, username=username)
    if user is None:
        # Se o dono do token não existir mais no db
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário do token não encontrado",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    # 4. Entrega o usuário "logado"
    return user


# -- Endpoint para registrar um novo usuário --
@app.post("/register", response_model=schemas.User, status_code=status.HTTP_201_CREATED)

# Cria um novo usuário no banco de dados
def create_user(user_data: schemas.UserCreate, db: Session = Depends(get_db)):
    hashed_pass = security.hash_password(user_data.password) # Hash da senha
    # Cria o objeto do modelo User
    new_user = models.User(
        username=user_data.username,
        email=user_data.email,
        nome=user_data.nome,
        cpf=user_data.cpf,
        hashed_password=hashed_pass # Ponto de segurança C3
    )
    
    try:
        db.add(new_user) # Adiciona o novo usuário à sessão
        db.commit() # Salva a transação no banco de dados
        db.refresh(new_user) # Atualiza o objeto new_user com os dados do banco (ex: id gerado)
        return new_user # Retorna o novo usuário criado
    except IntegrityError:
        db.rollback() # Desfaz a transação em caso de erro
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Usuáro já existe.")

# -- Endpoint para login e obtenção do token JWT --
@app.post("/login", response_model=schemas.Token)
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
): # Autentica um usuário e retorna um token de acesso
    
    user = get_user_by_username(db, form_data.username) #form_data.username é o campo 'username' do formulário de login

    # o security.verify_password compara a senha em texto puro com o hash salvo no banco
    if not user or not security.verify_password(form_data.password, user.hashed_password): # Se o usuário ou a senha NÃO EXISTEM/ESTÁ ERRADA:
    
        # NUNCA dizer se o erro foi no usuário ou na senha !!! 
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário ou senha incorretos.",
            headers={"WWW-Authenticate": "Bearer"},
        ) # Padrão de login
    
    # Passou do "if", o login é válido e cria-se um token
    token_data = {"sub": user.username}
    access_token = security.create_access_token(data = token_data)

    return {"access_token": access_token, "token_type": "bearer"} # retorna o token

# -- Endpoint Vulnerável (IDOR) --
@app.get("/profile/{user_id}", response_model=schemas.User)
# Vai buscar o perfil de um usuário pelo seu ID, mas não verifica se o usuário logado é o dono do perfil que está sendo solicitado.
def get_user_profile(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user) # "Vigia" do token
): 
    print(f"--- USUÁRIO LOGADO: {current_user.username} ---")
    
    # -- Correção da Vulnerabilidade A01:IDOR -- 

    # Estrutura condicional para checagem de autorização.
    """
    if current_user.id != user_id:
        raise HTTPException(
            status_code = status.HTTP_403_FORBIDDEN, # 403 acesso proibido
            detail = "Você não tem permissão para acessar este perfil !"
        )
    """

    user_profile = db.query(models.User).filter(models.User.id == user_id).first() # Esse código busca no banco qualquer user_id vindo da URL.
    # Mas se a condição de current_user.id == user_id, então ele busca no db com segurança.

    if user_profile is None:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail = "Usuário não encontrado"
        )
    
    # Ele retorna o perfil de 'user_id', mesmo que não seja o 'current_user'
    return user_profile


#Endpoint principal, só para sabermos que a API está rodando
@app.get("/")
def read_root():
    return {"message": "Welcome to AppSec Banking API!"}