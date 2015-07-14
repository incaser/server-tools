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

from openerp import models, fields, api

TYPE_RSA = crypto.TYPE_RSA
TYPE_DSA = crypto.TYPE_DSA


class KeyPair(models.Model):
    _name = 'openssl.key.pair'

    name = fields.Char(string='Name')
    public_key = fields.Text(
        string='Public key', readonly=True,
        states={'draft': [('readonly', False)]})
    private_key = fields.Text(
        string='Private key', readonly=True,
        states={'draft': [('readonly', False)]})
    type = fields.Selection([(TYPE_RSA, 'RSA'),
                             (TYPE_DSA, 'DSA')])
    size = fields.Selection([(1024, '1024'),
                             (2048, '2048'),
                             (4096, '4096')])
    partner_id = fields.Many2one(
        comodel_name='res.partner', string='Partner',
        help='Owner of the key. The only who can view, import and '
             'export the key.')
    state = fields.Selection([
        ('draft', 'Draft'),
        ('confirmed', 'Confirmed'),
        ('cancel', 'Cancelled'),
    ], string='State', readonly=True, default='draft')

    def create_key_pair(self, type, bits):
        """
        Create a public/private key pair.

        Arguments: type - Key type, must be one of TYPE_RSA and TYPE_DSA
                   bits - Number of bits to use in the key
        Returns:   The public/private key pair in a PKey object
        """
        pkey = crypto.PKey()
        pkey.generate_key(type, bits)
        return pkey

    @api.multi
    def generate_key(self):
        key = self.create_key_pair(self.type, self.size)
        self.public_key = key[:self.size]
        self.private_key = key[self.size:]
