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
#############################################################################

from openerp import models, fields, api
from openerp.tools.translate import _
from M2Crypto import X509
from datetime import datetime, timedelta

class generate_certificate(models.TransientModel):
    _name = 'openssl.generate_certificate'

    partner_id = fields.Many2one(comodel_name='res.partner', string='Partner')
    serial_number = fields.Integer(string='Serial number', default=1)
    version = fields.Integer(string='Version', default=2)
    date_begin = fields.Date(
        string='Begin date',
        default=(datetime.today() + timedelta(days=(0))).strftime('%Y-%m-%d'))
    date_end = fields.Date(
        string='Expiration date',
        default=(datetime.today() + timedelta(days=(365))).strftime('%Y-%m-%d'))
    name_c = fields.Char(string='Country (C)', size=2)
    name_sp = fields.Char(string='State or Province Name (ST/SP)', size=64)
    name_l = fields.Char(string='Locality Name (L)', size=64)
    name_o = fields.Char(string='Organization Name (O)', size=64)
    name_ou = fields.Char(string='Organization Unit Name (OU)', size=64)
    name_cn = fields.Char(string='Common name (CN)', size=64)
    name_gn = fields.Char(string='Given Name (GN)', size=64)
    name_sn = fields.Char(string='Surname (SN)', size=64)
    name_email = fields.Char(string='E-mail Addres (EMail)', size=64)
    name_serialnumber = fields.Char(
        string='Serial Number (serialNumber)', size=64)
    cert_type = fields.Selection([('entity', 'Entity'),
                                  ('ca', 'Common Auhtority'),])

    @api.onchange('partner_id')
    def onchange_partner_id(self):
        if self.partner_id:
            self.name_c = self.partner_id.country_id.code
            self.name_sp = self.partner_id.state_id.name
            self.name_l = self.partner_id.city
            self.name_o = self.partner_id.name
            self.name_cn = self.partner_id.name
            self.name_email = self.partner_id.email

    @api.multi
    def generate_certificate(self):
        active_ids = self._context['active_ids']
        certificate_obj = self.pool.get('openssl.certificate')
        r_ids = []
        for wizard in self.browse(cr, uid, ids):
            name = X509.X509_Name()
            if wizard.name_c:  name.C  = wizard.name_c
            if wizard.name_sp: name.SP = wizard.name_sp
            if wizard.name_l:  name.L  = wizard.name_l
            if wizard.name_o:  name.O  = wizard.name_o
            if wizard.name_ou: name.OU = wizard.name_ou
            if wizard.name_cn: name.CN = wizard.name_cn
            if wizard.name_gn: name.GN = wizard.name_gn
            if wizard.name_sn: name.SN = wizard.name_sn
            if wizard.name_email: name.EMail = wizard.name_email
            if wizard.name_serialnumber: name.serialNumber = wizard.name_serialnumber
            r = certificate_obj.generate_certificate(active_ids,
                                                name, ext=None,
                                                serial_number=wizard.serial_number,
                                                version=wizard.version,
                                                date_begin=datetime.strptime(wizard.date_begin, '%Y-%m-%d'),
                                                date_end=datetime.strptime(wizard.date_end, '%Y-%m-%d'))
            # r_ids.extend([ r[_id] for _id in active_ids ])
            # certificate_obj.action_validate(cr, uid, active_ids)
        # res_id = r_ids[0]
        return {
            'name': _('Request Certificate'),
            'res_model': 'openssl.certificate',
            'res_id': active_ids[0],
            'type': 'ir.actions.act_window',
            'view_id': False,
            'view_mode': 'form',
            'limit': 80,
        }

    def on_cancel(self, cr, uid, ids, context):
        return {}
