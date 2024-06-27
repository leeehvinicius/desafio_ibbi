# API Supermercado Melo

Esta é uma API para gerenciamento de produtos e categorias de um supermercado, utilizando FastAPI e SQLAlchemy com MySQL.

## Configuração do Ambiente

- Python 3.7 ou superior
- Instalação das dependências:
pip install fastapi uvicorn sqlalchemy pymysql passlib python-jose pydantic

## Configuração do Banco de Dados

Configure o URL do seu banco de dados MySQL em `DATABASE_URL` no arquivo `main.py`.

DATABASE_URL = "mysql+pymysql://usuario:senha@localhost/nome_do_banco"

## Execução da Aplicação

Para iniciar a aplicação, execute o seguinte comando:

uvicorn main

Isso iniciará o servidor de desenvolvimento em `http://localhost:8000`.

## Endpoints Disponíveis

- **GET /produtos/**: Lista todos os produtos disponíveis.
- **GET /produtos/{produto_id}/**: Retorna um produto específico pelo ID.
- **POST /produtos_save/**: Cria um novo produto.
- **PUT /produtos_put/{produto_id}/**: Atualiza um produto existente pelo ID.
- **DELETE /produtos/{produto_id}/**: Deleta um produto pelo ID.
- **GET /categorias/**: Lista todas as categorias disponíveis.
- **POST /categoria_save/**: Cria uma nova categoria.
- **POST /usuario_save/**: Cria um novo usuário.
- **GET /login/{login}/{senha}/**: Realiza o login do usuário.
- **POST /token/**: Gera um token de acesso para autenticação.
- **POST /user/**: Gera um token de acesso para autenticação.

## Autenticação

A API utiliza autenticação via JWT (JSON Web Token). É necessário gerar um token de acesso através do endpoint `/token` para acessar endpoints autenticados.

## Criação de Usuário

Para criar um novo usuário, utilize o endpoint `/user/`. Envie um POST com o seguinte corpo JSON:
```json
{
  "username": "username",
  "password": "password"
}


Execução do Projeto Angular
Para executar o projeto Angular, siga estes passos:

Certifique-se de ter o Node.js na versão 18 e o Angular CLI instalados na versão 16 (npm install -g @angular/cli@16).
No diretório do projeto Angular, execute o comando
npm install
Em seguida, execute o comando:
ng serve
Isso iniciará o servidor de desenvolvimento do Angular em http://localhost:4200.
