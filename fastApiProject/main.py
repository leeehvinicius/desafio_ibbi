from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import Column, Integer, String, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy import create_engine
from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware
from fastapi import File, UploadFile
import shutil

DATABASE_URL = "mysql+pymysql://root:Neilo0473@localhost/supermercado_melo"

# Configuração do SQLAlchemy
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Configurações de segurança
SECRET_KEY = "123456"  # Altere para sua chave secreta
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class Produto(Base):
    __tablename__ = "produto"
    id_prod = Column(Integer, primary_key=True, index=True)
    descricao_prod = Column(String(255), index=True)
    imagem_prod = Column(String(255))
    valor_prod = Column(Float)
    quantidade_prod = Column(Integer)
    id_login_fk = Column(Integer)
    id_categorias_fk = Column(Integer)

# Usuário para login
class Usuario(Base):
    __tablename__ = "usuario"
    id_usuario = Column(Integer, primary_key=True, index=True)
    nome_login = Column(String(255), index=True)
    senha_usuario = Column(String(255))

# Usuário para autenticação
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    hashed_password = Column(String(255))

class Categorias(Base):
    __tablename__ = "categorias"
    id_cat = Column(Integer, primary_key=True, index=True)
    descricao_cat = Column(String(50), unique=True, index=True)


# Criando as tabelas no banco de dados
Base.metadata.create_all(bind=engine)

app = FastAPI()

# Configuração do CORS (Cross-Origin Resource Sharing)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200"],  # URL do seu frontend Angular durante o desenvolvimento
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],  # Métodos HTTP permitidos
    allow_headers=["Authorization", "Content-Type"],  # Headers permitidos
)

class ProdutoCreate(BaseModel):
    descricao: str
    img: str
    valor: float
    quantidade: int
    id_login: int
    id_cat: int

class CategoriasCreate(BaseModel):
    descricao: str



class ProdutoUpdateCompra(BaseModel):
    quantidade: int

class UsuarioCreate(BaseModel):
        login: str
        senha: str


class ProdutoUpdate(BaseModel):
    descricao: str
    img: str
    valor: float
    quantidade: int
    id_login: int
    id_cat: int

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class UserCreate(BaseModel):
    username: str
    password: str

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(db, username: str):
    return db.query(User).filter(User.username == username).first()

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

# Dependência de sessão de banco de dados
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

# Rota para criar usuário
@app.post("/users/", response_model=UserCreate)
def create_user(user: UserCreate, db: SessionLocal = Depends(get_db)):
    db_user = get_user(db, user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    new_user = User(username=user.username, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# Rota para gerar token
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: SessionLocal = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Endpoint para ler todos os produtos (autenticado)
@app.get("/produtos/", dependencies=[Depends(get_current_user)])
async def read_produtos(db: SessionLocal = Depends(get_db), current_user: User = Depends(get_current_user)):
    produtos = db.query(Produto).filter(Produto.quantidade_prod > 0).all()
    return produtos

# Endpoint para deletar um produto pelo ID (autenticado)
@app.delete("/produtos/{produto_id}", dependencies=[Depends(get_current_user)])
async def delete_produto(produto_id: int, db: SessionLocal = Depends(get_db)):
    produto = db.query(Produto).filter(Produto.id_prod == produto_id).first()
    if not produto:
        raise HTTPException(status_code=404, detail="Produto não encontrado")
    db.delete(produto)
    db.commit()
    return {"message": "Produto deletado com sucesso!"}

# Endpoint para ler um produto pelo ID (autenticado)
@app.get("/produtos/{produto_id}", dependencies=[Depends(get_current_user)])
async def read_produto(produto_id: int, db: SessionLocal = Depends(get_db)):
    produto = db.query(Produto).filter(Produto.id_prod == produto_id).first()
    if not produto:
        raise HTTPException(status_code=404, detail="Produto não encontrado")
    return produto

# Endpoint para criar um novo produto (autenticado)
@app.post("/produtos_save/", dependencies=[Depends(get_current_user)])
async def create_produto(produto: ProdutoCreate, db: SessionLocal = Depends(get_db)):
    db_produto = Produto(
        descricao_prod=produto.descricao,
        imagem_prod=produto.img,
        quantidade_prod=produto.quantidade,
        valor_prod=produto.valor,
        id_login_fk=produto.id_login,
        id_categorias_fk=produto.id_cat
    )
    db.add(db_produto)
    db.commit()
    db.refresh(db_produto)
    return {"message": "Produto salvo com sucesso!"}

# Endpoint para atualizar um produto pelo ID (autenticado)
@app.put("/produtos_put/{produto_id}", dependencies=[Depends(get_current_user)])
async def update_produto(produto_id: int, produto: ProdutoUpdate, db: SessionLocal = Depends(get_db)):
    db_produto = db.query(Produto).filter(Produto.id_prod == produto_id).first()
    if not db_produto:
        raise HTTPException(status_code=404, detail="Produto não encontrado")
    db_produto.descricao_prod = produto.descricao
    db_produto.imagem_prod = produto.img
    db_produto.quantidade_prod = produto.quantidade
    db_produto.valor_prod = produto.valor
    db_produto.id_login_fk = produto.id_login
    db_produto.id_categorias_fk = produto.id_cat
    db.commit()
    db.refresh(db_produto)
    return {"message": "Produto editado com sucesso!"}

# Endpoint para criar um novo produto (autenticado)
@app.post("/usuario_save/", dependencies=[Depends(get_current_user)])
async def create_usuario(usuario: UsuarioCreate, db: SessionLocal = Depends(get_db)):
    db_usuario = Usuario(
        nome_login=usuario.login,
        senha_usuario=usuario.senha
    )
    db.add(db_usuario)
    db.commit()
    db.refresh(db_usuario)
    return {"message": "Usuario salvo com sucesso!"}


@app.get("/login/{login}/{senha}", dependencies=[Depends(get_current_user)])
async def read_usuario(login: str, senha: str, db: SessionLocal = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.nome_login == login, Usuario.senha_usuario == senha).first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Login não encontrado")

    # Se o usuário for encontrado, retornamos um dicionário com os dados do usuário e a mensagem de sucesso
    return {"usuario": usuario, "message": "Login realizado com sucesso"}


@app.put("/produtos_compra/{produto_id}", dependencies=[Depends(get_current_user)])
async def update_produto(produto_id: int, produto: ProdutoUpdateCompra, db: SessionLocal = Depends(get_db)):
    print(f"Received data: {produto}")  # Adicione este log
    db_produto = db.query(Produto).filter(Produto.id_prod == produto_id).first()
    if not db_produto:
        raise HTTPException(status_code=404, detail="Produto não encontrado")

    if produto.quantidade > db_produto.quantidade_prod:
        raise HTTPException(status_code=400, detail="Quantidade desejada não disponível")


    db_produto.quantidade_prod -= produto.quantidade

    db.commit()
    db.refresh(db_produto)
    return {"message": "Produto Comprado com sucesso!"}





@app.put("/produtos_compra_adicionar/{produto_id}", dependencies=[Depends(get_current_user)])
async def update_produto(produto_id: int, produto: ProdutoUpdateCompra, db: SessionLocal = Depends(get_db)):
    print(f"Received data: {produto}")  # Adicione este log
    db_produto = db.query(Produto).filter(Produto.id_prod == produto_id).first()
    if not db_produto:
        raise HTTPException(status_code=404, detail="Produto não encontrado")

    if produto.quantidade > db_produto.quantidade_prod:
        raise HTTPException(status_code=400, detail="Quantidade desejada não disponível")

    db_produto.quantidade_prod += produto.quantidade

    db.commit()
    db.refresh(db_produto)
    return {"message": "Produto Adicionado com sucesso!"}


# Endpoint para criar um nova Categoria (autenticado)
@app.post("/categoria_save/", dependencies=[Depends(get_current_user)])
async def create_categorias(categorias: CategoriasCreate, db: SessionLocal = Depends(get_db)):
    db_categoria = Categorias(
        descricao_cat=categorias.descricao,

    )
    db.add(db_categoria)
    db.commit()
    db.refresh(db_categoria)
    return {"message": "Categoria salva com sucesso!"}

# Endpoint para ler todos os Categorias (autenticado)
@app.get("/categorias/", dependencies=[Depends(get_current_user)])
async def read_categorias(db: SessionLocal = Depends(get_db), current_user: User = Depends(get_current_user)):
    categorias = db.query(Categorias).all()
    return categorias


