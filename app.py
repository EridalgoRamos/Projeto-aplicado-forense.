from flask import Flask, render_template_string, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import pandas as pd

app = Flask(__name__)
# O cookie de sessão precisa de uma chave. Em produção no Eixo 1, usaremos o .env
app.secret_key = 'chave_super_secreta_projeto_uncisal'

# ==============================================================================
# OWASP A02: Falhas Criptográficas (Cryptographic Failures)
# A senha 'admin123' nunca é salva ou comparada em texto puro.
# ==============================================================================
ADMIN_USER = 'admin'
ADMIN_HASH = generate_password_hash('admin123')

# ==============================================================================
# OWASP A01: Quebra de Controle de Acesso (Broken Access Control)
# Decorador que expulsa qualquer usuário não autenticado da página restrita.
# ==============================================================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Templates HTML (Front-end e Back-end unificados para o protótipo)
LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head><title>Login - Forense de Rede</title></head>
<body style="font-family: Arial; padding: 50px; text-align: center;">
    <h2>Acesso Restrito - Logs de Rede</h2>
    {% if erro %}
        <p style="color:red; font-weight: bold;">{{ erro }}</p>
    {% endif %}
    <form method="POST">
        <input type="text" name="username" placeholder="Usuário" required><br><br>
        <input type="password" name="password" placeholder="Senha" required><br><br>
        <button type="submit" style="padding: 10px 20px;">Entrar no Sistema</button>
    </form>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head><title>Dashboard de Logs</title></head>
<body style="font-family: Arial; padding: 20px;">
    <h2>Visualizador de Logs de Rede</h2>
    <p>Sessão ativa: <strong>{{ session['user'] }}</strong> | <a href="/logout">Sair (Logout)</a></p>
    <hr>
    <h3>Últimos Eventos Capturados</h3>
    <div>
        {{ tabela | safe }}
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    erro = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Validação do Hash
        if username == ADMIN_USER and check_password_hash(ADMIN_HASH, password):
            session['logged_in'] = True
            session['user'] = username
            return redirect(url_for('dashboard'))
        else:
            # ==============================================================================
            # OWASP A07: Falhas de Autenticação (Authentication Failures)
            # Mensagem estritamente genérica para evitar enumeração de usuários.
            # ==============================================================================
            erro = 'Credenciais inválidas.'
            
    return render_template_string(LOGIN_HTML, erro=erro)

@app.route('/dashboard')
@login_required
def dashboard():
    # Motor de Dados: Simulando a leitura de um arquivo CSV de logs com Pandas
    dados_forenses = {
        'Data/Hora': ['2026-09-19 10:00:15', '2026-09-19 10:05:22', '2026-09-19 10:15:00'],
        'IP Origem': ['192.168.1.100', '10.0.0.51', '172.16.0.8'],
        'Porta Destino': [443, 22, 80],
        'Protocolo': ['HTTPS', 'SSH', 'HTTP'],
        'Status': ['Tráfego Permitido', 'Bloqueado (Fail2Ban)', 'Tráfego Permitido']
    }
    df = pd.DataFrame(dados_forenses)
    
    # Converte o DataFrame do Pandas direto para uma tabela HTML limpa
    tabela_html = df.to_html(index=False, border=1, justify='center')
    
    return render_template_string(DASHBOARD_HTML, tabela=tabela_html)

@app.route('/logout')
def logout():
    session.clear() # Destrói a sessão criptografada
    return redirect(url_for('login'))

if __name__ == '__main__':
    # O modo debug=False é mandatório em produção (Security Misconfiguration)
    app.run(debug=False, host='0.0.0.0', port=5000)
