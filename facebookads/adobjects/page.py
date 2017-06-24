# Copyright 2014 Facebook, Inc.

# You are hereby granted a non-exclusive, worldwide, royalty-free license to
# use, copy, modify, and distribute this software in source code or binary
# form for use in connection with the web services and APIs provided by
# Facebook.

# As with any software that integrates with the Facebook platform, your use
# of this software is subject to the Facebook Developer Principles and
# Policies [http://developers.facebook.com/policy/]. This copyright notice
# shall be included in all copies or substantial portions of the software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

from facebookads.adobjects.event import Event
from facebookads.adobjects.leadgenform import LeadgenForm
from facebookads.adobjects.abstractcrudobject import AbstractCrudObject
from facebookads.adobjects.abstractobject import AbstractObject
from facebookads.adobjects.abstractcrudobject import AbstractCrudObject
from facebookads.adobjects.objectparser import ObjectParser
from facebookads.api import FacebookRequest
from facebookads.typechecker import TypeChecker
from facebookads.adobjects.helpers.adaccountmixin import AdAccountMixin
from facebookads.mixins import HasAdLabels
from facebookads.mixins import (
    CannotCreate,
    CannotDelete,
    CannotUpdate,
)


class Page(CannotCreate, CannotDelete, CannotUpdate, AbstractCrudObject):

    class Field(object):
        id = 'id'
        name = 'name'
        category = 'category'
        access_token = 'access_token'
        location = 'location'
        website = 'website'
        phone = 'phone'

    class Location(object):
        city = 'city'
        country = 'country'
        latitude = 'latitude'
        longitude = 'longitude'
        street = 'street'
        zip = 'zip'

    class AccessType:
        owner = 'OWNER'
        agency = 'AGENCY'

    class PermittedRoles:
        admin = 'ADMIN'
        general_user = 'GENERAL_USER'
        reports_only = 'REPORTS_ONLY'
        instagram_advertiser = 'INSTAGRAM_ADVERTISER'
        instagram_manager = 'INSTAGRAM_MANAGER'
        fb_employee_dso_advertiser = 'FB_EMPLOYEE_DSO_ADVERTISER'

    # @deprecated get_endpoint function is deprecated
    @classmethod
    def get_endpoint(cls):
        return 'accounts'

    def get_extended_access_token(self, fields=None, params=None, batch=None, pending=False):
        param_types = {
            'grant_type':        'string',
            'client_id':         'string',
            'client_secret':     'string',
            'fb_exchange_token': 'string',
        }
        enums = {
        }
        request = FacebookRequest(
            node_id='oauth',
            method='GET',
            endpoint='/access_token',
            api=self._api,
            param_checker=TypeChecker(param_types, enums),
            target_class=AbstractCrudObject,
            api_type='NODE',
            response_parser=ObjectParser(reuse_object=self),
        )

        # TODO: Create an actual object instead of using AbstractCrudObject with this list..
        request._accepted_fields = list(request._accepted_fields)
        request._accepted_fields.extend([
            'access_token', 'token_type'
        ])

        request.add_params(params)
        request.add_fields(fields)

        if batch is not None:
            request.add_to_batch(batch)
            return request
        elif pending:
            return request
        else:
            self.assure_call()
            return request.execute()

    def get_access_token_debug_details(self, fields=None, params=None, batch=None, pending=False):
        param_types = {
            'input_token':  'string',
            'access_token': 'string',
        }
        enums = {
        }
        request = FacebookRequest(
            node_id='debug_token',
            method='GET',
            endpoint='/',
            api=self._api,
            param_checker=TypeChecker(param_types, enums),
            target_class=AbstractCrudObject,
            api_type='NODE',
            response_parser=ObjectParser(reuse_object=self),
        )

        # TODO: Create an actual object instead of using AbstractCrudObject with this list..
        request._accepted_fields = list(request._accepted_fields)
        request._accepted_fields.extend([
            'app_id', 'application', 'expires_at', 'is_valid', 'issued_at', 'scopes', 'user_id'
        ])

        request.add_params(params)
        request.add_fields(fields)

        if batch is not None:
            request.add_to_batch(batch)
            return request
        elif pending:
            return request
        else:
            self.assure_call()
            return request.execute()

    def get_leadgen_forms(self, fields=None, params=None):
        """
        Returns all leadgen forms on the page
        """
        return self.iterate_edge(
            LeadgenForm,
            fields,
            params,
            endpoint='leadgen_forms',
        )

    def get_events(self, fields=None, params=None):
        """
        Returns all events on the page
        """
        return self.iterate_edge(Event, fields, params, endpoint='events')

    def get_picture(self, fields=None, params=None, batch=None, pending=False):
        from facebookads.adobjects.profilepicturesource import ProfilePictureSource
        param_types = {
            'height': 'int',
            'redirect': 'bool',
            'type': 'type_enum',
            'width': 'int',
        }
        enums = {
            'type_enum': ProfilePictureSource.Type.__dict__.values(),
        }
        request = FacebookRequest(
            node_id=self['id'],
            method='GET',
            endpoint='/picture',
            api=self._api,
            param_checker=TypeChecker(param_types, enums),
            target_class=ProfilePictureSource,
            api_type='EDGE',
            response_parser=ObjectParser(target_class=ProfilePictureSource),
        )
        request.add_params(params)
        request.add_fields(fields)

        if batch is not None:
            request.add_to_batch(batch)
            return request
        elif pending:
            return request
        else:
            self.assure_call()
            return request.execute()

    def get_agencies(self, fields=None, params=None, batch=None, pending=False):
        from facebookads.adobjects.business import Business
        param_types = {
        }
        enums = {
        }
        request = FacebookRequest(
            node_id=self['id'],
            method='GET',
            endpoint='/agencies',
            api=self._api,
            param_checker=TypeChecker(param_types, enums),
            target_class=Business,
            api_type='EDGE',
            response_parser=ObjectParser(target_class=Business),
        )
        request.add_params(params)
        request.add_fields(fields)

        if batch is not None:
            request.add_to_batch(batch)
            return request
        elif pending:
            return request
        else:
            self.assure_call()
            return request.execute()

    def create_agency(self, fields=None, params=None, batch=None, pending=False):
        from facebookads.adobjects.business import Business
        param_types = {
            'business': 'string',
            'permitted_roles': 'list<permitted_roles_enum>',
        }
        enums = {
            'permitted_roles_enum': Page.PermittedRoles.__dict__.values(),
        }
        request = FacebookRequest(
            node_id=self['id'],
            method='POST',
            endpoint='/agencies',
            api=self._api,
            param_checker=TypeChecker(param_types, enums),
            target_class=Business,
            api_type='EDGE',
            response_parser=ObjectParser(target_class=Business),
        )
        request.add_params(params)
        request.add_fields(fields)

        if batch is not None:
            request.add_to_batch(batch)
            return request
        elif pending:
            return request
        else:
            self.assure_call()
            return request.execute()

    def get_all_user_permissions(self, fields=None, params=None, batch=None, pending=False):
        param_types = {
        }
        enums = {
        }
        request = FacebookRequest(
            node_id=self['id'],
            method='GET',
            endpoint='/userpermissions',
            api=self._api,
            param_checker=TypeChecker(param_types, enums),
            target_class=AbstractCrudObject,
            api_type='EDGE',
            response_parser=ObjectParser(target_class=AbstractCrudObject),
        )
        request.add_params(params)
        request.add_fields(fields)

        if batch is not None:
            request.add_to_batch(batch)
            return request
        elif pending:
            return request
        else:
            self.assure_call()
            return request.execute()

    def get_user_permissions(self, fields=None, params=None, batch=None, pending=False):
        param_types = {
        }
        enums = {
        }
        request = FacebookRequest(
            node_id=self['id'],
            method='GET',
            endpoint='/userpermissions',
            api=self._api,
            param_checker=TypeChecker(param_types, enums),
            target_class=AbstractCrudObject,
            api_type='EDGE',
            response_parser=ObjectParser(target_class=AbstractCrudObject),
        )
        request.add_params(params)
        request.add_fields(fields)

        if batch is not None:
            request.add_to_batch(batch)
            return request
        elif pending:
            return request
        else:
            self.assure_call()
            return request.execute()

    def create_user_permission(self, fields=None, params=None, batch=None, pending=False):
        param_types = {
            'business': 'string',
            'user': 'string',
            'role': 'role_enum',
        }
        enums = {
            'role_enum': [
                'ADMIN',
                'GENERAL_USER',
                'REPORTS_ONLY',
            ],
        }
        request = FacebookRequest(
            node_id=self['id'],
            method='POST',
            endpoint='/userpermissions',
            api=self._api,
            param_checker=TypeChecker(param_types, enums),
            target_class=AbstractCrudObject,
            api_type='EDGE',
            response_parser=ObjectParser(target_class=AbstractCrudObject),
        )
        request.add_params(params)
        request.add_fields(fields)

        if batch is not None:
            request.add_to_batch(batch)
            return request
        elif pending:
            return request
        else:
            self.assure_call()
            return request.execute()

    @classmethod
    def _get_field_enum_info(cls):
        field_enum_info = {}
        field_enum_info['AccessType'] = Page.AccessType.__dict__.values()
        field_enum_info['PermittedRoles'] = Page.PermittedRoles.__dict__.values()
        return field_enum_info
