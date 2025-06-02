import functools

from flask import (
    Blueprint, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import abort

from flaskr.db import get_db

FLASH_MESSAGES_KEY = '_my_flashes'

def my_flash(message, category='message'):
    if FLASH_MESSAGES_KEY not in session:
        session[FLASH_MESSAGES_KEY] = []
    session[FLASH_MESSAGES_KEY].append((category, message))

def get_my_flashed_messages(with_categories=False):
    messages = session.pop(FLASH_MESSAGES_KEY, [])
    if with_categories:
        return messages
    else:
        return [msg for cat, msg in messages]


bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Nome de usuário é obrigatório.'
        elif not password:
            error = 'Senha é obrigatória.'

        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
            except db.IntegrityError:
                error = f"O usuário '{username}' já está registrado."
            else:
                my_flash("Registro realizado com sucesso! Faça login.")
                return redirect(url_for("auth.login"))

        my_flash(error)

    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    error = None

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()

        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Nome de usuário ou senha incorretos.'
        elif not check_password_hash(user['password'], password):
            error = 'Nome de usuário ou senha incorretos.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            my_flash(f"Bem-vindo(a), {user['username']}!")
            return redirect(url_for('listagem.index'))

    if error:
        my_flash(error)

    return render_template('auth/login.html')

@bp.route('/logout')
def logout():
    session.clear()
    my_flash("Você foi desconectado(a).")
    return redirect(url_for('listagem.index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            my_flash("Você precisa estar logado(a) para acessar esta página.")
            return redirect(url_for('auth.login'))

        return view(**kwargs)
    return wrapped_view


def get_user_by_id(user_id, check_logged_in_user=True):
    user = get_db().execute(
        'SELECT * FROM user WHERE id = ?', (user_id,)
    ).fetchone()

    if user is None:
        abort(404, f"Usuário com ID {user_id} não encontrado.")

    if check_logged_in_user and user['id'] != g.user['id']:
        abort(403, "Você não tem permissão para acessar este perfil.")

    return user

@bp.route('/profile')
@login_required
def profile():
    return render_template('auth/profile.html', user=g.user)

@bp.route('/profile/edit', methods=('GET', 'POST'))
@login_required
def edit_profile():
    user = g.user

    if request.method == 'POST':
        new_username = request.form['username']
        new_password = request.form['password']
        error = None

        if not new_username:
            error = 'Nome de usuário é obrigatório.'

        if error is None:
            db = get_db()
            update_query = 'UPDATE user SET username = ?'
            params = [new_username]

            if new_password:
                update_query += ', password = ?'
                params.append(generate_password_hash(new_password))

            update_query += ' WHERE id = ?'
            params.append(user['id'])

            try:
                db.execute(update_query, tuple(params))
                db.commit()
                my_flash("Perfil atualizado com sucesso!")
                return redirect(url_for('auth.profile'))

            except db.IntegrityError:
                error = f"O nome de usuário '{new_username}' já está em uso."
        
        my_flash(error)

    return render_template('auth/edit_profile.html', user=user)

@bp.route('/profile/delete', methods=('POST',))
@login_required
def delete_profile():
    user_id = g.user['id']

    db = get_db()
    
    db.execute('DELETE FROM user WHERE id = ?', (user_id,))
    db.commit()
    
    session.clear()
    my_flash("Sua conta foi excluída com sucesso.")
    return redirect(url_for('index'))