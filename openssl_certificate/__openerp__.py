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
{
    'name': "SSL Certificate Genarator",
    'category': 'Tools',
    'version': '1.0',
    'depends': [
        'base',
    ],
    'external_dependencies': {
        'python': ['OpenSSL'],
    },
    'data': [
        'views/key_pair_view.xml',
        'views/certificate_view.xml',
        'wizard/generate_certificate.xml',
        'views/menu_view.xml'
    ],
    'qweb': [
    ],
    'js': [
    ],
    'author': 'Incaser Informatica S.L., '
              'Odoo Community Association (OCA)',
    'website': 'http://www.incaser.es',
    'license': 'AGPL-3',
    'demo': [],
    'test': [],
    'installable': True,
    # 'auto_install':False,
    # 'application':False,
}
