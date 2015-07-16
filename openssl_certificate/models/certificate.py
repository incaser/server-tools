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
import hashlib
import string
from random import choice

from openerp import models, fields, api

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
                       readonly=True,
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
    ], 'State', readonly=True)
    password = fields.Char()
    status = fields.Char(
        compute='_get_status', string='Status', help='Certificate Status')

    def get_serial(self):
        #Serial Generation - Serial number must be unique for each certificate,
        md5_hash = hashlib.md5()
        md5_hash.update('pepe')#TODO
        serial = int(md5_hash.hexdigest(), 36)
        return serial

    def get_attach_binary(self, cert):
        return self.env['ir.attachment'].search(
            [('model','=','openssl.certificate'),('id','=', cert.id)])[0].db_datas

    @api.multi
    def create_certificate(self, partner, ca_cert):
        # ca_crt ='/home/sergio/desarrollo/CRTDatabase/Certificados Comcas/Comcas_CA_Root.crt'
        # ca_key ='/home/sergio/desarrollo/CRTDatabase/Certificados Comcas/Comcas_CA_Root.pem'


        ca_pem = self.get_attach(ca_cert)
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_pem)
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_pem)

        # The CA stuff is loaded from the same folder as this script
        # ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(ca_pem).read())
        # The last parameter is the password for your CA key file
        # ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(ca_pem).read())

        # key = crypto.PKey()
        # key.generate_key(crypto.TYPE_RSA, 4096)

        pkey_obj = self.env['openssl.key.pair']
        vals = {'name': 'Cert_%s' % (self.name),
                'type': crypto.TYPE_RSA,
                'size': 4096
                }
        pkey_record = pkey_obj.create(vals)
        pkey = pkey_record.generate_key()
        self.keypair_id = pkey_record


        cert = crypto.X509()
        cert.get_subject().C = self.partner_id.country_id.code
        cert.get_subject().ST = self.partner_id.state_id.name
        cert.get_subject().L = self.partner_id.city
        cert.get_subject().O = self.partner_id.company_id.name
        cert.get_subject().OU = "website"
        cert.get_subject().CN = self.partner_id.name
        cert.get_subject().emailAddress = self.partner_id.email
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)
        cert.add_extensions([
          crypto.X509Extension("basicConstraints", True, "CA:FALSE"),
          crypto.X509Extension("keyUsage", True, "digitalSignature, keyEncipherment, dataEncipherment"),
          crypto.X509Extension("subjectKeyIdentifier", False, "hash", subject=cert),
          crypto.X509Extension("authorityKeyIdentifier", False, "keyid:always", subject=ca_cert, issuer=ca_cert),
          crypto.X509Extension("extendedKeyUsage", False, "clientAuth"),
          crypto.X509Extension("nsCertType", False, "client, email"),
          crypto.X509Extension("nsComment", False, "xca certificate"),
          ])

        cert.set_serial_number(self.get_serial())
        cert.set_version(2)
        cert.set_issuer(ca_cert.get_subject())
        cert.set_pubkey(pkey)
        cert.sign(ca_key, "sha256")

        # The key and cert files are dumped and their paths are returned
        # key_path = os.path.join(os.path.dirname(__file__),"domains/"+domain.replace('.','_')+".key")
        # domain_key = open(key_path,"w")
        # domain_key.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        #
        # cert_path = os.path.join(os.path.dirname(__file__),"domains/"+domain.replace('.','_')+".crt")
        # domain_cert = open(cert_path,"w")
        # domain_cert.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

        self.crt = self.cert_to_PKCS12(cert, pkey)

        # image = base64.encodestring(fn.read())

        # string_key = cStringIO.StringIO()
        # string_key.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        # self.crt = string_key.getvalue()
        # string_key.close()
        return cert

    def cert_to_PKCS12(self, cert, pkey):
        certPKCS12 = crypto.PKCS12()
        certPKCS12.set_certificate(cert)
        certPKCS12.set_privatekey(pkey)
        self.password = self.gen_passwd(8)
        pk_str = certPKCS12.export(self.password, iter=2048, maciter=1)

        vals={
            'name': 'Cert-%s.p12' % (self.partner_id.name),
            'datas_fname': 'Certi - 1',
            'res_model': 'openssl.certificate',
            'res_id': self.id,
            'db_datas': pk_str,
            }
        self.env['ir.attachment'].create(vals)
        return pk_str

    def gen_passwd(self, n):
        """
        Generador de passwords
        Usando choice para seleccionar una, la fuente de datos lo da string.letters
        Para usar tambien numeros, string.digits
        """
        return ''.join([choice(string.letters + string.digits) for i in range(n)])