from flask import Blueprint, render_template
from flask_login import current_user
from sqlalchemy.orm import selectinload
from app.models import ApiToken

bp = Blueprint('main', __name__)

@bp.route('/')
@bp.route('/index')
def index():
    tokens = []
    if current_user.is_authenticated:
        tokens = ApiToken.query.filter_by(user_id=current_user.id)\
            .options(selectinload(ApiToken.domains))\
            .order_by(ApiToken.added_at.desc()).all()
    return render_template('index.html', title='主页', tokens=tokens)
