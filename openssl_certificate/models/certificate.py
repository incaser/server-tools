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

from OpenSSL import crypto, SSL
import os, hashlib

from openerp import models, fields, api

class Certificate(models.Model):
    _name = 'openssl.certificate'
    name = fields.Char(string='Name')
    csr = fields.Text('Request Certificate',
                       readonly=True,
                       states={'draft': [('readonly', False)]},
                       help='Certificate Request in PEM format.')
    crt = fields.Text('Certificate',
                       readonly=True,
                       states={'draft': [('readonly', False)],
                               'waiting': [('readonly', False)]},
                       help='Certificate in PEM format.')
    keypair_id = fields.Many2one(
        comodel_name='openssl.key.pair', string='Pair Key')
    state = fields.Selection([
        ('draft', 'Draft'),
        ('waiting', 'Waiting'),
        ('confirmed', 'Confirmed'),
        ('cancel', 'Cancelled')
    ], 'State', readonly=True)

    def get_serial(self):
        #Serial Generation - Serial number must be unique for each certificate,
        md5_hash = hashlib.md5()
        md5_hash.update('pepe')#TODO
        serial = int(md5_hash.hexdigest(), 36)
        return serial

    @api.multi
    def createCertificate(self, partner):
        # The CA stuff is loaded from the same folder as this script
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(ca_crt).read())
        # The last parameter is the password for your CA key file
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(ca_key).read(), "owtf-d

        key = crypto.PKey()
        key.generate_key( crypto.TYPE_RSA, 2048)

        cert = crypto.X509()
        cert.get_subject().C = "IN"
        cert.get_subject().ST = "AP"
        cert.get_subject().L = "127.0.0.1"
        cert.get_subject().O = "OWTF"
        cert.get_subject().OU = "Inbound-Proxy"
        cert.get_subject().CN = 'xxxx' # This is where the domain fits
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)
        cert.set_serial_number(self.get_serial())
        cert.set_issuer(ca_cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(ca_key, "sha1")

        # The key and cert files are dumped and their paths are returned
        key_path = os.path.join(os.path.dirname(__file__),"domains/"+domain.replace('.','_')+".key")
        domain_key = open(key_path,"w")
        domain_key.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

        cert_path = os.path.join(os.path.dirname(__file__),"domains/"+domain.replace('.','_')+".crt")
        domain_cert = open(cert_path,"w")
        domain_cert.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        return cert