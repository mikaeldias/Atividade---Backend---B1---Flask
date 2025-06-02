import os
from flask import Flask, render_template

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'todo.sqlite'),
    )

    if test_config is None:
        app.config.from_pyfile('config.py', silent=True)
    else:
        app.config.from_mapping(test_config)

    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    @app.route('/hello')
    def hello():
        return 'Hello, World!'

    @app.route('/favicon.ico')
    def favicon():
        return '', 204

    from . import db
    db.init_app(app)

    from . import auth
    app.register_blueprint(auth.bp)
    from .auth import get_my_flashed_messages
    app.jinja_env.globals['get_my_flashed_messages'] = get_my_flashed_messages


    from . import listagem
    app.register_blueprint(listagem.bp)

    app.add_url_rule('/', endpoint='index')

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404

    return app