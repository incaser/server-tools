# -*- coding: utf-8 -*-
# Python source code encoding : https://www.python.org/dev/peps/pep-0263/
##############################################################################
#
#    OpenERP, Open Source Management Solution
#    This module copyright :
#        (c) 2015 Incaser Informatica, SL (
#                   Castellon, Spain, http://www.incaser.es)
#                 Carlos Dauden <carlos@incaser.es>
#                 Sergio Teruel <sergio@incaser.es>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
##############################################################################

from OpenSSL import crypto
import base64
import hashlib
import string
from random import choice

from openerp import models, fields, api
from openerp.exceptions import Warning
from openerp.tools.translate import _


class Certificate(models.Model):
    _name = 'openssl.certificate'

    @api.one
    def _get_status(self):
        self.status = 'en pruebas'

    name = fields.Char(string='Name')
    type = fields.Selection(
        [('ca', 'Common Authority'),
         ('entity', 'entity')],string='Type', default='entity')
    partner_id = fields.Many2one(
        comodel_name='res.partner', string='Partner',required=True)
    csr = fields.Text('Request Certificate',
                       readonly=True,
                       states={'draft': [('readonly', False)]},
                       help='Certificate Request in PEM format.')
    crt = fields.Text('Certificate',
                       states={'draft': [('readonly', False)],
                               'waiting': [('readonly', False)]},
                       help='Certificate in PEM format.')
    keypair_id = fields.Many2one(
        comodel_name='openssl.key.pair', string='Pair Key',
        ondelete='restrict')
    state = fields.Selection([
        ('draft', 'Draft'),
        ('waiting', 'Waiting'),
        ('confirmed', 'Confirmed'),
        ('cancel', 'Cancelled')
    ], 'State', readonly=True, default='draft')
    password = fields.Char()
    status_email = fields.Selection(
        [('to_send', 'To Send'),
         ('send', 'Send'),
         ('not_send', 'Not Send')], string='Email Send', default='to_send')
    # status = fields.Char(
    #     compute='_get_status', string='Status', help='Certificate Status')

    def get_serial(self):
        #Serial Generation - Serial number must be unique for each certificate,
        md5_hash = hashlib.md5()
        md5_hash.update('pepe')#TODO
        serial = int(md5_hash.hexdigest(), 36)
        return serial

    @api.model
    def get_default_ca_cert(self):
        param_obj = self.env['ir.config_parameter']
        ca_cert_id = param_obj.get_param('openssl_certificate.root_id', False)
        return self.env['openssl.certificate'].browse(eval(ca_cert_id))

    @api.one
    def generate_certificate(self):
        ca_cert_reg = self.get_default_ca_cert()
        if not ca_cert_reg:
            raise Warning(_('Certificate Error'),
                             _('Have not CA Root certificate selected, '
                               'contact with administrator'))
        ca_cert = crypto.load_certificate(
            crypto.FILETYPE_PEM, ca_cert_reg.crt)
        ca_key = crypto.load_privatekey(
            crypto.FILETYPE_PEM, ca_cert_reg.keypair_id.private_key)
        pkey_obj = self.env['openssl.key.pair']
        vals = {'name': 'Cert_%s' % (self.name),
                'partner_id': self.partner_id.id,
                'type': crypto.TYPE_RSA,
                'size': 2048
                }
        pkey_record = pkey_obj.create(vals)
        pkey = pkey_record.generate_key()
        self.keypair_id = pkey_record
        cert = crypto.X509()
        subject_data = self.get_cert_subject_data()
        for key in subject_data.keys():
            setattr(cert.get_subject(), key, subject_data[key])
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)
        cert.add_extensions([
          crypto.X509Extension(
              "basicConstraints", True,
              "CA:FALSE"),
          crypto.X509Extension(
              "keyUsage", True,
              "digitalSignature, keyEncipherment, dataEncipherment"),
          crypto.X509Extension(
              "subjectKeyIdentifier", False,
              "hash", subject=cert),
          crypto.X509Extension(
              "authorityKeyIdentifier", False,
              "keyid:always,issuer:always", subject=ca_cert, issuer=ca_cert),
          crypto.X509Extension(
              "extendedKeyUsage", False,
              "clientAuth"),
          crypto.X509Extension(
              "nsCertType", False,
              "client, email"),
          crypto.X509Extension(
              "nsComment", False,
              "xca certificate"),
          ])
        cert.set_serial_number(self.get_serial())
        cert.set_version(2)
        cert.set_issuer(ca_cert.get_subject())
        cert.set_pubkey(pkey)
        cert.sign(ca_key, "sha256")

        vals = {'crt': crypto.dump_certificate(crypto.FILETYPE_PEM, cert),
                'state': 'confirmed'}
        self.write(vals)

        self.cert_to_PKCS12(cert, pkey)
        return True

    def get_cert_subject_data(self):
        data ={
            'O': self.partner_id.country_id.code,
            'ST': self.partner_id.state_id.name,
            'L': self.partner_id.city,
            'O': self.partner_id.company_id.name,
            'OU': "website",
            'CN': self.partner_id.name,
            'emailAddress': self.partner_id.email}
        return data


    def cert_to_PKCS12(self, cert, pkey):
        certPKCS12 = crypto.PKCS12()
        certPKCS12.set_certificate(cert)
        certPKCS12.set_privatekey(pkey)
        self.password = self.gen_passwd(8)
        pk_str = certPKCS12.export(self.password, iter=2048, maciter=1)

        vals={
            'name': 'Cert-%s.p12' % (self.partner_id.name),
            'datas_fname': 'Cert-%s.p12' % (self.partner_id.name),
            'res_model': 'openssl.certificate',
            'res_id': self.id,
            'db_datas': pk_str,
            }
        self.env['ir.attachment'].create(vals)
        return True

    def gen_passwd(self, n):
        """
        Generador de passwords
        Usando choice para seleccionar una, la fuente de datos lo da string.letters
        Para usar tambien numeros, string.digits
        """
        return ''.join([choice(string.letters + string.digits) for i in range(n)])

    @api.model
    def mass_create_certificate(self):
        partner_ids = self._context.get('active_ids', False)
        partners = self.env['res.partner'].browse(partner_ids)
        cert_ids = []
        for partner in partners:
            vals = {'name': partner.name,
                    'partner_id': partner.id}
            new_cert = self.create(vals)
            cert_ids.append(new_cert.id)
            new_cert.generate_certificate()

        action = {
            'name': 'Certificates',
            'type': 'ir.actions.act_window',
            'res_model': 'openssl.certificate',
            'view_type': 'form',
            'view_mode': 'tree,form',
            'domain': [('id', 'in', cert_ids)],
            'context': self._context,
        }
        return action

    @api.model
    def mass_create_send_certificate(self):
        partner_ids = self._context.get('active_ids', False)
        partners = self.env['res.partner'].browse(partner_ids)
        cert_ids = []
        for partner in partners:
            vals = {'name': partner.name,
                    'partner_id': partner.id}
            new_cert = self.create(vals)
            cert_ids.append(new_cert.id)
            new_cert.generate_certificate()

        ctx = self._context.copy()
        ctx['active_ids'] = cert_ids
        action = {
            'name': 'Send Certificates',
            'type': 'ir.actions.act_window',
            'res_model': 'openssl.send_certificate',
            'view_type': 'form',
            'view_mode': 'form',
            'target': 'new',
            'context': ctx,
        }
        return action

    def get_attach(self):
        attach_obj = self.env['ir.attachment']
        attach = attach_obj.search(
            [('res_model', '=', 'openssl.certificate'),
             ('res_id', '=', self.id)])
        return attach

    @api.model
    def get_default_mail_template(self):
        param_obj = self.env['ir.config_parameter']
        template_id = param_obj.get_param(
            'openssl_certificate.mail_template_id', False)
        return self.env['email.template'].browse(eval(template_id))


    @api.multi
    def send_email(self):
        template_id = self.get_default_mail_template()
        mail_obj = self.env['mail.mail']
        base_url = self.env['ir.config_parameter'].get_param('web.base.url')
        rec_email = self.filtered(lambda r: r.partner_id.email)
        mails_rendered = template_id.generate_email_batch(
            template_id.id, rec_email.ids)

        for cert in rec_email:
            vals = mails_rendered[cert.id]
            attach = cert.get_attach()
            if vals:
                vals['attachment_ids'] = [(6, 0, [attach.id])]
                # vals['partner_ids'] = [(6, 0, vals['partner_ids'])]
                mail_obj.create(vals)
        return rec_email.write({'status_email': 'send'})
