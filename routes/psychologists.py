from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import db_features as dbf
import database as db
from utils.validation import is_valid_email
from utils.sensitive_content import contains_hate_speech

apoio = Blueprint('apoio', __name__)

ESPECIALIDADES = [
    'Ansiedade', 'Depressão', 'Luto', 'Relacionamentos', 'Autoestima', 'Trauma',
    'Estresse', 'Pânico', 'Família', 'Adolescentes', 'LGBTQIA+', 'Dependência química',
]
ESTADOS = ['AC', 'AL', 'AP', 'AM', 'BA', 'CE', 'DF', 'ES', 'GO', 'MA', 'MT', 'MS', 'MG',
           'PA', 'PB', 'PR', 'PE', 'PI', 'RJ', 'RN', 'RS', 'RO', 'RR', 'SC', 'SP', 'SE', 'TO']


def _admin_ok():
    if not session.get('admin_logged_in') or not session.get('admin_user_id'):
        return False
    user = db.get_user_by_id(session['admin_user_id'])
    return bool(user and user['is_admin'])


@apoio.route('/apoio')
def apoio_publico():
    especialidade = request.args.get('especialidade') or None
    estado = request.args.get('estado') or None
    modalidade = request.args.get('modalidade') or None
    psicologos = dbf.get_approved_psychologists(especialidade, estado, modalidade)
    return render_template(
        'apoio/lista.html',
        psicologos=psicologos,
        especialidades=ESPECIALIDADES,
        estados_ativos=dbf.get_approved_psych_states(),
        f_especialidade=especialidade, f_estado=estado, f_modalidade=modalidade,
    )


@apoio.route('/apoio/voluntario', methods=['GET', 'POST'])
def voluntario():
    if request.method == 'GET':
        return render_template('apoio/cadastro.html', especialidades=ESPECIALIDADES, estados=ESTADOS, form={})

    f = request.form
    name = f.get('name', '').strip()
    contact_email = f.get('contact_email', '').strip()
    crp = f.get('crp', '').strip()
    estado = f.get('estado', '').strip()
    cidade = f.get('cidade', '').strip()
    especialidades = ', '.join(f.getlist('especialidades')).strip()
    bio = f.get('bio', '').strip()
    contact_link = f.get('contact_link', '').strip()
    modalidade = f.get('modalidade', 'ambos').strip()
    photo_url = f.get('photo_url', '').strip() or None

    errors = []
    if len(name) < 3:
        errors.append('Informe seu nome completo.')
    if not is_valid_email(contact_email):
        errors.append('Informe um e-mail profissional válido.')
    if not crp:
        errors.append('Informe seu CRP.')
    if estado not in ESTADOS:
        errors.append('Selecione o estado.')
    if not especialidades:
        errors.append('Selecione ao menos uma especialidade.')
    if len(bio) < 20:
        errors.append('Escreva uma bio com pelo menos 20 caracteres.')
    if modalidade not in ('online', 'presencial', 'ambos'):
        modalidade = 'ambos'
    if contains_hate_speech(name) or contains_hate_speech(bio):
        errors.append('O texto contém expressões que não podemos aceitar.')

    if errors:
        for err in errors:
            flash(err, 'error')
        return render_template('apoio/cadastro.html', especialidades=ESPECIALIDADES, estados=ESTADOS, form=f)

    if dbf.create_psychologist(name, contact_email, crp, estado, cidade, especialidades,
                               bio, contact_link, modalidade, photo_url):
        flash('Recebemos seu cadastro 💙 Nossa equipe vai revisar com cuidado e, se aprovado, '
              'seu perfil aparece na página de apoio.', 'success')
        return redirect(url_for('apoio.apoio_publico'))

    flash('Não conseguimos registrar agora. Tente de novo em instantes.', 'error')
    return render_template('apoio/cadastro.html', especialidades=ESPECIALIDADES, estados=ESTADOS, form=f)


@apoio.route('/admin/psicologos')
def admin_psicologos():
    if not _admin_ok():
        return redirect(url_for('admin.login'))
    return render_template(
        'admin/psychologists.html',
        pendentes=dbf.get_psychologists_by_status('pending'),
        todos=dbf.get_all_psychologists(),
    )


@apoio.route('/admin/psicologos/<int:psych_id>/<acao>', methods=['POST'])
def admin_psicologo_acao(psych_id, acao):
    if not _admin_ok():
        return redirect(url_for('admin.login'))
    status = {'aprovar': 'approved', 'rejeitar': 'rejected'}.get(acao)
    if status and dbf.set_psychologist_status(psych_id, status):
        flash('Psicólogo aprovado.' if status == 'approved' else 'Cadastro rejeitado.', 'success')
    return redirect(url_for('apoio.admin_psicologos'))
