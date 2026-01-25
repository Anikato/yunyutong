"""
API 路由 - 提供 JSON API 接口
"""
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from app.models import ApiToken, Domain
from app.extensions import db

bp = Blueprint('api', __name__, url_prefix='/api')


@bp.route('/tokens/reorder', methods=['POST'])
@login_required
def reorder_tokens():
    """
    更新凭证排序顺序
    
    请求体:
    {
        "order": [1, 3, 2, 4]  // 凭证 ID 列表，按新顺序排列
    }
    """
    data = request.get_json()
    
    if not data or 'order' not in data:
        return jsonify({'error': '缺少 order 参数'}), 400
    
    order = data['order']
    
    if not isinstance(order, list):
        return jsonify({'error': 'order 必须是数组'}), 400
    
    try:
        # 更新每个凭证的排序顺序
        for index, token_id in enumerate(order):
            token = ApiToken.query.filter_by(
                id=token_id, 
                user_id=current_user.id
            ).first()
            
            if token:
                token.sort_order = index + 1
        
        db.session.commit()
        return jsonify({'success': True, 'message': '排序已更新'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@bp.route('/tokens/<int:token_id>/domains/reorder', methods=['POST'])
@login_required
def reorder_domains(token_id):
    """
    更新域名排序顺序
    
    请求体:
    {
        "order": [1, 3, 2, 4]  // 域名 ID 列表，按新顺序排列
    }
    """
    # 验证凭证归属
    token = ApiToken.query.filter_by(
        id=token_id, 
        user_id=current_user.id
    ).first_or_404()
    
    data = request.get_json()
    
    if not data or 'order' not in data:
        return jsonify({'error': '缺少 order 参数'}), 400
    
    order = data['order']
    
    if not isinstance(order, list):
        return jsonify({'error': 'order 必须是数组'}), 400
    
    try:
        # 更新每个域名的排序顺序
        for index, domain_id in enumerate(order):
            domain = Domain.query.filter_by(
                id=domain_id, 
                api_token_id=token_id
            ).first()
            
            if domain:
                domain.sort_order = index + 1
        
        db.session.commit()
        return jsonify({'success': True, 'message': '排序已更新'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@bp.route('/tokens/<int:token_id>/sort_order', methods=['POST'])
@login_required
def update_token_sort_order(token_id):
    """
    更新单个凭证的排序值
    
    请求体:
    {
        "sort_order": 5
    }
    """
    token = ApiToken.query.filter_by(
        id=token_id, 
        user_id=current_user.id
    ).first_or_404()
    
    data = request.get_json()
    
    if not data or 'sort_order' not in data:
        return jsonify({'error': '缺少 sort_order 参数'}), 400
    
    try:
        sort_order = int(data['sort_order'])
        token.sort_order = sort_order
        db.session.commit()
        return jsonify({'success': True, 'sort_order': sort_order})
    
    except ValueError:
        return jsonify({'error': 'sort_order 必须是整数'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@bp.route('/domains/<int:domain_id>/sort_order', methods=['POST'])
@login_required
def update_domain_sort_order(domain_id):
    """
    更新单个域名的排序值
    
    请求体:
    {
        "sort_order": 5
    }
    """
    domain = Domain.query.get_or_404(domain_id)
    
    # 验证域名所属凭证的归属
    token = ApiToken.query.filter_by(
        id=domain.api_token_id, 
        user_id=current_user.id
    ).first_or_404()
    
    data = request.get_json()
    
    if not data or 'sort_order' not in data:
        return jsonify({'error': '缺少 sort_order 参数'}), 400
    
    try:
        sort_order = int(data['sort_order'])
        domain.sort_order = sort_order
        db.session.commit()
        return jsonify({'success': True, 'sort_order': sort_order})
    
    except ValueError:
        return jsonify({'error': 'sort_order 必须是整数'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
