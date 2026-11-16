"""Template documentation is text, not code or part of executable approval."""
from flask import jsonify, request, session
from core.database import db, TaskTemplate

MAX_DESCRIPTION = 32000


def validate_description(value):
    if value is None:
        return ''
    if not isinstance(value,str) or len(value)>MAX_DESCRIPTION or '\x00' in value:
        raise ValueError('Description must be text of up to 32,000 characters')
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        raise ValueError('Description contains invalid characters') from None
    return value.replace('\r\n','\n').replace('\r','\n')


def register(bp):
    @bp.route('/api/infrastructure/templates/<tid>/description',methods=['GET','PATCH'])
    def template_description(tid):
        from .routes import can, can_access_template_library_entry, can_edit_template, write_infra_audit
        if session.get('api_key_auth'):
            return jsonify(success=False,message='Use an interactive session for template documentation'),403
        if not (can('run_tasks') or can('manage_templates')):
            return jsonify(success=False,message='Template access denied'),403
        template=db.session.get(TaskTemplate,tid)
        if not template or not can_access_template_library_entry(template):
            return jsonify(success=False,message='Template not found'),404
        if request.method=='GET':
            return jsonify(success=True,description=template.description or '',can_edit=bool(can('manage_templates') and can_edit_template(template)))
        if session.get('api_key_auth') or not can('manage_templates') or not can_edit_template(template):
            return jsonify(success=False,message='Template editing is locked or not permitted'),403
        data=request.get_json(silent=True)
        try:
            if not isinstance(data,dict) or 'description' not in data:
                raise ValueError('Provide a description')
            value=validate_description(data['description'])
        except ValueError as exc:
            return jsonify(success=False,message=str(exc)),400
        template.description=value
        write_infra_audit('Template Description Updated','task_template',template.id,{'characters':len(value)})
        db.session.commit()
        return jsonify(success=True,description=value)
