from flask import Flask, render_template, redirect, url_for, flash,session,request,abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError 
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField,SubmitField 
from wtforms.validators import Length, EqualTo,Email, DataRequired, ValidationError
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, UserMixin, logout_user, login_required, current_user
import stripe
from functools import wraps
from datetime import datetime
from collections import defaultdict


login_manager = LoginManager()
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///ecommerce.db"
app.config["SECRET_KEY"]="1679e2ce3daa83c9c220a933db1bb34009"
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager.init_app(app)
login_manager.login_view="page_login"
login_manager.login_message="por favor faça o login"
login_manager.login_message_category="info"

# configurando as chaves da API da Stripe 
stripe.api_key = "chave-secreta"

STRIPE_PUBLIC_KEY = "chave-publica"

app.config["STRIPE_PUBLIC_KEY"] = STRIPE_PUBLIC_KEY

def admin_required(func):
      @wraps(func)
      def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
          abort(403)  # Código HTTP 403 - Acesso negado
        return func(*args, **kwargs)
      return decorated_view

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Modelos
from flask_login import UserMixin  # Importe o UserMixin

class User(UserMixin, db.Model):  # herda de UserMixin
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)

    def get_id(self):
        return str(self.id)

    @property
    def is_authenticated(self):
        return True if self.is_active else False
    
    # criptografa a senha
    @property
    def senhacrip(self):
        return self.senhacrip

    @senhacrip.setter
    def senhacrip(self, password_text):
        self.password = bcrypt.generate_password_hash(password_text).decode('utf-8')
    
    #converte a senha para texo claro para poder validar a senha na hora do login
    def converte_senha(self,senha_texto_claro):
        return bcrypt.check_password_hash(self.password,senha_texto_claro)

    

class Produtos(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(80), nullable=False)
    descricao = db.Column(db.String(300), nullable=False)
    preco = db.Column(db.Integer, nullable=False)
    estoque = db.Column(db.Integer, nullable=False)
    imagen = db.Column(db.String(60), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('produtos', lazy=True))
    
    @property
    def Formatavalor(self):
      if len(str(self.preco)) >= 4:
        return f"R$ {str(self.preco)[:-3]}, {str(self.preco)[-3:]}"
      else:
        return f"R$ {self.valor}"

from datetime import datetime

class Pedidos(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    itens_comprados = db.Column(db.String(80), unique=True, nullable=False)
    valor_total = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(60), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('pedidos', lazy=True))
    data_pedido = db.Column(db.DateTime, default=datetime.utcnow)  # Adicionando a data de criação
#formularios
class Cadusuarios(FlaskForm):
  def validation_nome(self,check_nome):
    name = User.query.filter_by(username=check_nome.data).first()
    if name:
      raise ValidationError("nome de usuario ja existe, ppr favor tente outro nome")
      
  def validation_email(self,check_email):
    email = User.query.filter_by(email=check_email.data).first()
    if email:
      raise ValidationError("email ja existe, por favor tente outro email")
      
  nome = StringField(label="nome",validators=[DataRequired()])
  email = StringField(label="E-mail", validators=[DataRequired(),Email()])
  senha1 = PasswordField(label="digite uma senha por favor.", validators=[DataRequired(),Length(2,8)])
  senha2 = PasswordField(label="digite uma senha por favor.", validators=[DataRequired(),EqualTo("senha1")])
  submit = SubmitField(label="cadastrar")
  
class Login_Form(FlaskForm):
  usuario = StringField(label="usuario",validators=[DataRequired()])
  senha = PasswordField(label="senha",validators=[DataRequired()])
  submit = SubmitField(label="log in")


class ProdutoForm(FlaskForm):
    nome = StringField("Nome", validators=[DataRequired()])
    descricao = StringField("Descrição", validators=[DataRequired()])
    preco = StringField("Preço", validators=[DataRequired()])
    estoque = StringField("Estoque", validators=[DataRequired()])
    imagem = StringField("Imagem", validators=[DataRequired()])
    submit = SubmitField("Salvar")



# Rotas
@app.route("/")
def home_page():
    produtos = Produtos.query.all()
    return render_template("index.html", produtos=produtos)

@app.route("/produto/<int:id>")
@login_required
def Produto_page(id):
    produto = Produtos.query.get_or_404(id)
    return render_template("produto.html", produto=produto)

@app.route("/loja")
@login_required
def Loja_page():
    produtos = Produtos.query.all()  # Pega todos os produtos
    return render_template("loja.html", produtos=produtos)

@app.route("/carrinho")
@login_required
def Carrinho_page():
    carrinho = session.get("carrinho", {})  # Pega os produtos no carrinho
    produtos = Produtos.query.filter(Produtos.id.in_(carrinho.keys())).all()  # Busca os produtos do carrinho no banco
    
    total = sum(produto.preco * carrinho[str(produto.id)] for produto in produtos)

    return render_template("carrinho.html", produtos=produtos, carrinho=carrinho, total=total)
    
@app.route("/adicionar/<int:produto_id>",methods=["POST","GET"])
@login_required
def adicionar_ao_carrinho(produto_id):
    produto = Produtos.query.get_or_404(produto_id)

    carrinho = session.get("carrinho", {})

    if str(produto_id) in carrinho:
        carrinho[str(produto_id)] += 1
    else:
        carrinho[str(produto_id)] = 1

    session["carrinho"] = carrinho
    flash(f"{produto.nome} adicionado ao carrinho!", "success")
    return redirect(url_for("Loja_page"))
    
@app.route("/remover/<int:produto_id>")
@login_required
def remover_do_carrinho(produto_id):
    carrinho = session.get("carrinho", {})

    if str(produto_id) in carrinho:
        del carrinho[str(produto_id)]
        session["carrinho"] = carrinho
        flash("Produto removido do carrinho!", "info")

    return redirect(url_for("Carrinho_page"))

@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    carrinho = session.get("carrinho", {})
    produtos = Produtos.query.filter(Produtos.id.in_(carrinho.keys())).all()
    
    total = sum(produto.preco * carrinho[str(produto.id)] for produto in produtos)

    if request.method == "POST":
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=["card", "boleto"],  # Atualize conforme o suporte do seu dashboard
            line_items=[
                {
                    "price_data": {
                        "currency": "brl",
                        "product_data": {"name": "Compra no E-commerce"},
                        "unit_amount": int(total * 100),  # Multiplicando por 100 para trabalhar com centavos
                    },
                    "quantity": 1,
                }
            ],
            mode="payment",
            success_url=url_for("pagamento_sucesso", _external=True),
            cancel_url=url_for("pagamento_falha", _external=True),
        )
        return redirect(checkout_session.url)
    return render_template("checkout.html", produtos=produtos, carrinho=carrinho, total=total)
    
@app.route("/pagamento_sucesso")
def pagamento_sucesso():
    carrinho = session.get("carrinho", {})
    produtos = Produtos.query.filter(Produtos.id.in_(carrinho.keys())).all()

    total = sum(produto.preco * carrinho[str(produto.id)] for produto in produtos)
    itens_comprados = ", ".join([produto.nome for produto in produtos])  # Lista de produtos comprados

    # Criação do pedido após o pagamento
    novo_pedido = Pedidos(
        itens_comprados=itens_comprados,
        valor_total=f"R$ {total}",
        status="Concluído",
        user_id=current_user.id
    )

    # Salvando o pedido no banco
    db.session.add(novo_pedido)
    db.session.commit()

    # Limpa o carrinho após a compra
    session.pop("carrinho", None)

    flash("Pagamento aprovado! Pedido concluído.", "success")
    return redirect(url_for("Loja_page"))

@app.route("/pagamento_falha")
def pagamento_falha():
    flash("O pagamento não foi concluído. Tente novamente.", "danger")
    return redirect(url_for("Carrinho_page"))

@app.route("/cad_usuarios", methods=["POST", "GET"])
def Cadastrar_usu():
    form = Cadusuarios()
    if form.validate_on_submit():
        novo_usuario = User(
            username=form.nome.data,
            email=form.email.data,
            senhacrip=form.senha1.data
        )
        try:
            db.session.add(novo_usuario)
            db.session.commit()
            flash(f"Parabéns {novo_usuario.username}, cadastro realizado com sucesso!", category="success")
            return redirect(url_for("Loja_page"))
        except IntegrityError:
            db.session.rollback()  # Reverte a operação para evitar erro no banco
            flash("Erro: Este e-mail já está cadastrado. Tente outro.", category="danger")

    if form.errors:
        for err in form.errors.values():
            flash(err, category="danger")

    return render_template("cadastrar.html", form=form)


@app.route("/login", methods=["GET","POST"])
def page_login():
    form = Login_Form()
    if form.validate_on_submit():
        usuario_logado = User.query.filter_by(username=form.usuario.data).first()
        if usuario_logado and usuario_logado.converte_senha(senha_texto_claro=form.senha.data):
            login_user(usuario_logado)
            flash(f"login realizado com sucesso! Olá  {usuario_logado.username}",category="success")
            return redirect(url_for("Loja_page"))
        else:
            flash(f"senha ou email inválido", category="danger")
    return render_template("login_page.html",form=form)
    
    
@app.route("/logout")
def page_logout():
  logout_user()
  flash(f"até logo", category="info")
  return redirect(url_for("home_page"))
  
@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    form = ProdutoForm()
    produtos = Produtos.query.all()
    pedidos = Pedidos.query.all()

    # Agrupar vendas por mês
    vendas_por_mes = defaultdict(float)

    for pedido in pedidos:
        valor = float(pedido.valor_total.replace('R$', '').replace('.', '').replace(',', '.'))

        # Usando a nova coluna 'data_pedido' para pegar a data do pedido
        data_pedido = pedido.data_pedido  
        mes = data_pedido.strftime('%b') 
        
        vendas_por_mes[mes] += valor

    # Meses de janeiro a dezembro
    meses_ordenados = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    vendas_ordenadas = [vendas_por_mes.get(mes, 0) for mes in meses_ordenados]

    return render_template(
        "dashboard.html",
        produtos=produtos,
        pedidos=pedidos,
        form=form,
        vendas=vendas_ordenadas,
        meses=meses_ordenados
    )

@app.route("/admin/produto/novo", methods=["GET", "POST"])
@login_required
@admin_required
def novo_produto():
    form = ProdutoForm()
    if form.validate_on_submit():
        novo_produto = Produtos(
            nome=form.nome.data,
            descricao=form.descricao.data,
            preco=form.preco.data,
            estoque=form.estoque.data,
            imagen=form.imagem.data,
            user_id=current_user.id
        )
        db.session.add(novo_produto)
        db.session.commit()
        flash("Produto cadastrado com sucesso!", "success")
        return redirect(url_for("admin_dashboard"))
    return render_template("novo_produto.html", form=form)



@app.route("/admin/produto/editar/<int:id>", methods=["GET", "POST"])
@login_required
@admin_required
def editar_produto(id):
    produto = Produtos.query.get_or_404(id)
    
    if request.method == "POST":
        produto.nome = request.form["nome"]
        produto.descricao = request.form["descricao"]
        produto.preco = request.form["preco"]
        produto.estoque = request.form["estoque"]
        produto.imagen = request.form["imagen"]

        db.session.commit()
        flash("Produto atualizado com sucesso!", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("editar_produto.html", produto=produto)


@app.route("/admin/produto/deletar/<int:id>")
@login_required
@admin_required
def deletar_produto(id):
    produto = Produtos.query.get_or_404(id)
    db.session.delete(produto)
    db.session.commit()
    flash("Produto removido com sucesso!", "success")
    return redirect(url_for("admin_dashboard"))



if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)