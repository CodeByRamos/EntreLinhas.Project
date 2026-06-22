from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import db_features as dbf
from utils.sensitive_content import contains_hate_speech

cartas = Blueprint('cartas', __name__)

_PRESETS = {'30': 30, '90': 90, '180': 180, '365': 365}


def _require_login():
    if 'user_id' not in session:
        flash('Entre na sua conta para guardar uma carta.', 'error')
        return redirect(url_for('auth.login', next=url_for('cartas.minhas_cartas')))
    return None


@cartas.route('/cartas')
def minhas_cartas():
    redirect_login = _require_login()
    if redirect_login:
        return redirect_login
    letters = dbf.get_user_letters(session['user_id'])
    return render_template('cartas/lista.html', letters=letters)


@cartas.route('/cartas/nova', methods=['GET', 'POST'])
def nova_carta():
    redirect_login = _require_login()
    if redirect_login:
        return redirect_login

    if request.method == 'GET':
        return render_template('cartas/nova.html', form={})

    f = request.form
    title = f.get('title', '').strip() or None
    content = f.get('content', '').strip()
    prazo = f.get('prazo', '')
    data_custom = f.get('data_custom', '').strip()

    if len(content) < 10:
        flash('Escreva pelo menos algumas linhas pra sua carta.', 'error')
        return render_template('cartas/nova.html', form=f)
    if contains_hate_speech(content) or (title and contains_hate_speech(title)):
        flash('Esse texto traz expressões que não podemos guardar. Reescreva com cuidado.', 'error')
        return render_template('cartas/nova.html', form=f)

    now = datetime.utcnow()
    if prazo in _PRESETS:
        open_at = now + timedelta(days=_PRESETS[prazo])
    elif prazo == 'custom' and data_custom:
        try:
            open_at = datetime.strptime(data_custom, '%Y-%m-%d')
        except ValueError:
            flash('Data inválida. Use o seletor de data.', 'error')
            return render_template('cartas/nova.html', form=f)
        if open_at <= now:
            flash('Escolha uma data no futuro.', 'error')
            return render_template('cartas/nova.html', form=f)
    else:
        flash('Escolha quando a carta deve abrir.', 'error')
        return render_template('cartas/nova.html', form=f)

    if dbf.create_future_letter(session['user_id'], title, content, open_at):
        flash('Sua carta está guardada. Você vai reencontrá-la quando a data chegar. 💌', 'success')
        return redirect(url_for('cartas.minhas_cartas'))

    flash('Não conseguimos guardar a carta agora. Tente de novo.', 'error')
    return render_template('cartas/nova.html', form=f)


@cartas.route('/cartas/<int:letter_id>/abrir', methods=['POST'])
def abrir_carta(letter_id):
    redirect_login = _require_login()
    if redirect_login:
        return redirect_login
    ok, message = dbf.open_future_letter(letter_id, session['user_id'])
    flash(message, 'success' if ok else 'error')
    return redirect(url_for('cartas.minhas_cartas'))
