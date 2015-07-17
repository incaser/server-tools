
from openerp.osv import fields
from openerp.osv.orm import TransientModel
from openerp.tools.safe_eval import safe_eval


class base_config_settings(TransientModel):
    _inherit = 'base.config.settings'

    def set_openssl_certificate_root_id(self, cr, uid, ids, context=None):
        config = self.browse(cr, uid, ids[0], context=context)
        icp = self.pool['ir.config_parameter']
        icp.set_param(
            cr, uid, 'openssl_certificate.root_id',
            repr(config.openssl_certificate_root_id.id))

    def get_default_openssl_certificate_root_id(
            self, cr, uid, ids, context=None):
        icp = self.pool['ir.config_parameter']
        return {
            'openssl_certificate_root_id': safe_eval(icp.get_param(
                cr, uid, 'openssl_certificate.root_id', 'False')),
        }

    def set_openssl_certificate_mail_template_id(self, cr, uid, ids, context=None):
        config = self.browse(cr, uid, ids[0], context=context)
        icp = self.pool['ir.config_parameter']
        icp.set_param(
            cr, uid, 'openssl_certificate.mail_template_id',
            repr(config.openssl_certificate_mail_template_id.id))

    def get_default_openssl_certificate_mail_template_id(
            self, cr, uid, ids, context=None):
        icp = self.pool['ir.config_parameter']
        return {
            'openssl_certificate_mail_template_id': safe_eval(icp.get_param(
                cr, uid, 'openssl_certificate.mail_template_id', 'False')),
        }


    _columns = {
        'openssl_certificate_root_id': fields.many2one(
            'openssl.certificate', string='CA Certificate',
            domain=[('type', '=', 'ca')]),
        'openssl_certificate_mail_template_id': fields.many2one(
            'email.template', string='Mail Template'),
    }
