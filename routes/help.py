from flask import Blueprint, redirect, url_for

support = Blueprint('support', __name__)


@support.route('/ajuda')
def ajuda():
    """Rota antiga: Ajuda foi unificada com Apoio. Mantida só para não quebrar links."""
    return redirect(url_for('apoio.apoio_publico'), code=301)
