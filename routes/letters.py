from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import db_features as dbf
from utils.sensitive_content import evaluate_post_content
from extensions import limiter

cartas = Blueprint('cartas', __name__)

MAX_OPEN_LETTERS = 5  # anti-spam: cartas originais em circulação por pessoa

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
    # Mesma camada de moderação dos desabafos: ataque de ódio é barrado antes de salvar.
    if evaluate_post_content((title + ' ' + content) if title else content).get('block_publication'):
        flash('Essa carta traz uma ofensa que fere outras pessoas e não pode ser guardada assim. '
              'O EntreLinhas é um espaço de cuidado — reescreva com respeito para continuar.', 'error')
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
        flash('Sua carta está guardada. Você vai reencontrá-la quando a data chegar.', 'success')
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


# ---------------------------------------------------------------------------
# Cartas para Desconhecidos
# ---------------------------------------------------------------------------

@cartas.route('/cartas/desconhecidos')
def desconhecidos():
    redir = _require_login()
    if redir:
        return redir
    uid = session['user_id']
    return render_template(
        'cartas/desconhecidos.html',
        my_letters=dbf.get_my_stranger_letters(uid),
        replies=dbf.get_received_replies(uid),
        unread=dbf.count_unread_replies(uid),
        open_count=dbf.count_open_letters_by_author(uid),
        max_open=MAX_OPEN_LETTERS,
    )


@cartas.route('/cartas/desconhecidos/escrever', methods=['POST'])
@limiter.limit('6 per hour; 20 per day')
def escrever_desconhecido():
    redir = _require_login()
    if redir:
        return redir
    uid = session['user_id']
    content = request.form.get('content', '').strip()
    if len(content) < 10:
        flash('Escreva ao menos algumas linhas na sua carta.', 'error')
        return redirect(url_for('cartas.desconhecidos'))
    if len(content) > 2000:
        flash('Sua carta ficou longa demais. Tente resumir um pouco.', 'error')
        return redirect(url_for('cartas.desconhecidos'))
    if evaluate_post_content(content).get('block_publication'):
        flash('Essa carta traz uma ofensa que fere outras pessoas e não pode ser enviada assim. Reescreva com cuidado.', 'error')
        return redirect(url_for('cartas.desconhecidos'))
    if dbf.count_open_letters_by_author(uid) >= MAX_OPEN_LETTERS:
        flash('Você já tem várias cartas em circulação. Espere algumas respostas antes de enviar outra.', 'info')
        return redirect(url_for('cartas.desconhecidos'))
    if dbf.create_stranger_letter(uid, content):
        flash('Sua carta partiu. Em algum momento, alguém vai abri-la.', 'success')
    else:
        flash('Não conseguimos enviar sua carta agora. Tente de novo.', 'error')
    return redirect(url_for('cartas.desconhecidos'))


@cartas.route('/cartas/desconhecidos/receber', methods=['POST'])
@limiter.limit('40 per hour')
def receber_desconhecido():
    redir = _require_login()
    if redir:
        return redir
    letter = dbf.deliver_random_letter(session['user_id'])
    if not letter:
        flash('Por enquanto não há cartas novas para você. Volte daqui a pouco — ou deixe a sua para alguém encontrar.', 'info')
        return redirect(url_for('cartas.desconhecidos'))
    return redirect(url_for('cartas.ler_desconhecido', letter_id=letter['id']))


@cartas.route('/cartas/desconhecidos/ler/<int:letter_id>')
def ler_desconhecido(letter_id):
    redir = _require_login()
    if redir:
        return redir
    letter = dbf.get_delivered_letter(letter_id, session['user_id'])
    if not letter:
        flash('Essa carta não está disponível para você.', 'error')
        return redirect(url_for('cartas.desconhecidos'))
    return render_template('cartas/ler_desconhecido.html', letter=letter)


@cartas.route('/cartas/desconhecidos/<int:letter_id>/responder', methods=['POST'])
@limiter.limit('20 per hour')
def responder_desconhecido(letter_id):
    redir = _require_login()
    if redir:
        return redir
    uid = session['user_id']
    letter = dbf.get_delivered_letter(letter_id, uid)
    if not letter:
        flash('Essa carta não está disponível para você.', 'error')
        return redirect(url_for('cartas.desconhecidos'))
    content = request.form.get('content', '').strip()
    if len(content) < 5:
        flash('Escreva um pouco mais na sua resposta.', 'error')
        return redirect(url_for('cartas.ler_desconhecido', letter_id=letter_id))
    if len(content) > 2000:
        content = content[:2000]
    if evaluate_post_content(content).get('block_publication'):
        flash('Sua resposta traz uma ofensa que não podemos enviar. Reescreva com cuidado.', 'error')
        return redirect(url_for('cartas.ler_desconhecido', letter_id=letter_id))
    if dbf.respond_to_letter(uid, letter_id, content):
        flash('Sua resposta foi entregue a quem escreveu. Obrigado por estar ali.', 'success')
    else:
        flash('Não conseguimos enviar sua resposta agora.', 'error')
    return redirect(url_for('cartas.desconhecidos'))


@cartas.route('/cartas/desconhecidos/<int:letter_id>/encaminhar', methods=['POST'])
def encaminhar_desconhecido(letter_id):
    redir = _require_login()
    if redir:
        return redir
    uid = session['user_id']
    if dbf.get_delivered_letter(letter_id, uid):
        dbf.set_delivery_action(letter_id, uid, 'forwarded')
        flash('Tudo bem. A carta segue para outra pessoa responder.', 'info')
    nxt = dbf.deliver_random_letter(uid)
    if nxt:
        return redirect(url_for('cartas.ler_desconhecido', letter_id=nxt['id']))
    return redirect(url_for('cartas.desconhecidos'))


@cartas.route('/cartas/desconhecidos/<int:letter_id>/apenas-ler', methods=['POST'])
def apenas_ler_desconhecido(letter_id):
    redir = _require_login()
    if redir:
        return redir
    uid = session['user_id']
    if dbf.get_delivered_letter(letter_id, uid):
        dbf.set_delivery_action(letter_id, uid, 'read')
    flash('Carta guardada no silêncio. Às vezes, ler já basta.', 'success')
    return redirect(url_for('cartas.desconhecidos'))


@cartas.route('/cartas/desconhecidos/<int:letter_id>/denunciar', methods=['POST'])
@limiter.limit('20 per hour')
def denunciar_desconhecido(letter_id):
    redir = _require_login()
    if redir:
        return redir
    uid = session['user_id']
    if dbf.get_delivered_letter(letter_id, uid):
        dbf.report_stranger_letter(letter_id, uid)
    flash('Obrigado por avisar. A moderação vai olhar com cuidado.', 'success')
    return redirect(url_for('cartas.desconhecidos'))
