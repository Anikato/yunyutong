from flask import Blueprint, render_template, request
from flask_login import current_user
from sqlalchemy.orm import selectinload
from sqlalchemy import func
from app.models import ApiToken, Domain

bp = Blueprint('main', __name__)

@bp.route('/')
@bp.route('/index')
def index():
    tokens = []
    sort_by = request.args.get('sort', 'custom')  # 默认使用自定义排序
    
    if current_user.is_authenticated:
        query = ApiToken.query.filter_by(user_id=current_user.id)\
            .options(selectinload(ApiToken.domains))
        
        # 根据排序参数选择排序方式
        if sort_by == 'name':
            query = query.order_by(ApiToken.name.asc())
        elif sort_by == 'name_desc':
            query = query.order_by(ApiToken.name.desc())
        elif sort_by == 'provider':
            query = query.order_by(ApiToken.provider_type.asc(), ApiToken.name.asc())
        elif sort_by == 'date':
            query = query.order_by(ApiToken.added_at.desc())
        elif sort_by == 'date_asc':
            query = query.order_by(ApiToken.added_at.asc())
        elif sort_by == 'domains':
            # 按域名数量排序（多到少）
            query = query.outerjoin(Domain)\
                .group_by(ApiToken.id)\
                .order_by(func.count(Domain.id).desc())
        elif sort_by == 'domains_asc':
            # 按域名数量排序（少到多）
            query = query.outerjoin(Domain)\
                .group_by(ApiToken.id)\
                .order_by(func.count(Domain.id).asc())
        else:
            # 自定义排序：sort_order 优先，然后按添加时间
            query = query.order_by(
                ApiToken.sort_order.asc(),
                ApiToken.added_at.desc()
            )
        
        tokens = query.all()
    
    return render_template('index.html', title='主页', tokens=tokens, current_sort=sort_by)
