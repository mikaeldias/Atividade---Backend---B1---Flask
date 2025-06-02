from flask import (
    Blueprint, g, redirect, render_template, request, url_for
)
from werkzeug.exceptions import abort

from flaskr.auth import login_required, my_flash
from flaskr.db import get_db

bp = Blueprint('listagem', __name__)

@bp.route('/')
@login_required
def index():
    db = get_db()
    task_lists = db.execute(
        'SELECT tl.id, tl.name, tl.created, tl.author_id, u.username'
        ' FROM task_list tl JOIN user u ON tl.author_id = u.id'
        ' WHERE tl.author_id = ?'
        ' ORDER BY tl.created DESC',
        (g.user['id'],)
    ).fetchall()
    return render_template('listagem/lists.html', task_lists=task_lists)

def get_task_list(id, check_author=True):
    task_list = get_db().execute(
        'SELECT tl.id, tl.name, tl.created, tl.author_id, u.username'
        ' FROM task_list tl JOIN user u ON tl.author_id = u.id'
        ' WHERE tl.id = ?',
        (id,)
    ).fetchone()

    if task_list is None:
        abort(404, f"Lista de tarefas com ID {id} não encontrada.")

    if check_author and task_list['author_id'] != g.user['id']:
        abort(403, "Você não tem permissão para acessar esta lista de tarefas.")

    return task_list

@bp.route('/lists/create', methods=('GET', 'POST'))
@login_required
def create_list():
    if request.method == 'POST':
        name = request.form['name']
        error = None

        if not name:
            error = 'O nome da lista é obrigatório.'

        if error is not None:
            my_flash(error)
        else:
            db = get_db()
            db.execute(
                'INSERT INTO task_list (name, author_id) VALUES (?, ?)',
                (name, g.user['id'])
            )
            db.commit()
            my_flash(f"Lista '{name}' criada com sucesso!")
            return redirect(url_for('listagem.index'))

    return render_template('listagem/create_list.html')

@bp.route('/lists/<int:id>/update', methods=('GET', 'POST'))
@login_required
def update_list(id):
    task_list = get_task_list(id)

    if request.method == 'POST':
        name = request.form['name']
        error = None

        if not name:
            error = 'O nome da lista é obrigatório.'

        if error is not None:
            my_flash(error)
        else:
            db = get_db()
            db.execute(
                'UPDATE task_list SET name = ? WHERE id = ?',
                (name, id)
            )
            db.commit()
            my_flash(f"Lista '{name}' atualizada com sucesso!")
            return redirect(url_for('listagem.index'))

    return render_template('listagem/update_list.html', task_list=task_list)

@bp.route('/lists/<int:id>/delete', methods=('POST',))
@login_required
def delete_list(id):
    get_task_list(id)
    db = get_db()
    db.execute('DELETE FROM task_list WHERE id = ?', (id,))
    db.commit()
    my_flash("Lista de tarefas excluída com sucesso!")
    return redirect(url_for('listagem.index'))

@bp.route('/lists/<int:list_id>/tasks')
@login_required
def tasks_in_list(list_id):
    task_list = get_task_list(list_id)
    db = get_db()
    tasks = db.execute(
        'SELECT t.id, t.description, t.completed, t.created, t.list_id, u.username'
        ' FROM task t JOIN user u ON t.author_id = u.id'
        ' WHERE t.list_id = ? AND t.author_id = ?'
        ' ORDER BY t.created DESC',
        (list_id, g.user['id'])
    ).fetchall()
    return render_template('listagem/tasks_in_list.html', task_list=task_list, tasks=tasks)

def get_task(id, check_author=True):
    task = get_db().execute(
        'SELECT t.id, t.description, t.completed, t.created, t.list_id, u.username, t.author_id'
        ' FROM task t JOIN user u ON t.author_id = u.id'
        ' WHERE t.id = ?',
        (id,)
    ).fetchone()

    if task is None:
        abort(404, f"Tarefa com ID {id} não encontrada.")

    if check_author and task['author_id'] != g.user['id']:
        abort(403, "Você não tem permissão para acessar esta tarefa.")

    return task

@bp.route('/lists/<int:list_id>/tasks/create', methods=('GET', 'POST'))
@login_required
def create_task(list_id):
    task_list = get_task_list(list_id)

    if request.method == 'POST':
        description = request.form['description']
        error = None

        if not description:
            error = 'A descrição da tarefa é obrigatória.'

        if error is not None:
            my_flash(error)
        else:
            db = get_db()
            db.execute(
                'INSERT INTO task (description, list_id, author_id, completed) VALUES (?, ?, ?, ?)',
                (description, list_id, g.user['id'], 0)
            )
            db.commit()
            my_flash("Tarefa criada com sucesso!")
            return redirect(url_for('listagem.tasks_in_list', list_id=list_id))

    return render_template('listagem/create_task.html', task_list=task_list)

@bp.route('/tasks/<int:id>/update', methods=('GET', 'POST'))
@login_required
def update_task(id):
    task = get_task(id)

    if request.method == 'POST':
        description = request.form['description']
        completed = 'completed' in request.form

        error = None
        if not description:
            error = 'A descrição da tarefa é obrigatória.'

        if error is not None:
            my_flash(error)
        else:
            db = get_db()
            db.execute(
                'UPDATE task SET description = ?, completed = ? WHERE id = ?',
                (description, 1 if completed else 0, id)
            )
            db.commit()
            my_flash("Tarefa atualizada com sucesso!")
            return redirect(url_for('listagem.tasks_in_list', list_id=task['list_id']))

    return render_template('listagem/update_task.html', task=task)

@bp.route('/tasks/<int:id>/delete', methods=('POST',))
@login_required
def delete_task(id):
    task = get_task(id)
    list_id = task['list_id']

    db = get_db()
    db.execute('DELETE FROM task WHERE id = ?', (id,))
    db.commit()
    my_flash("Tarefa excluída com sucesso!")
    return redirect(url_for('listagem.tasks_in_list', list_id=list_id))