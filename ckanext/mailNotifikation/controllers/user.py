import logging
from urllib import quote

from pylons import config

import uuid
import ckan.lib.base as base
import ckan.model as model
import ckan.lib.helpers as h
import ckan.new_authz as new_authz
import ckan.logic as logic
import ckan.logic.schema as schema
import ckan.lib.captcha as captcha
import ckan.lib.mailer as mailer
import ckan.lib.navl.dictization_functions as dictization_functions
import ckan.plugins as p
import datetime
from dateutil.relativedelta import relativedelta
import psycopg2
import smtplib
import re

import base64
from ckan.common import _, c, g, request, response

log = logging.getLogger(__name__)

 
abort = base.abort
render = base.render
validate = base.validate

check_access = logic.check_access
get_action = logic.get_action
NotFound = logic.NotFound
NotAuthorized = logic.NotAuthorized
ValidationError = logic.ValidationError

DataError = dictization_functions.DataError
unflatten = dictization_functions.unflatten

from ckan.controllers.user import UserController
class CustomUserController(UserController):

    def _encode(self,key, clear):
        enc = []
        for i in range(len(clear)):
            key_c = key[i % len(key)]
            enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
            enc.append(enc_c)
        return base64.urlsafe_b64encode("".join(enc))

    def _decode(self,key, enc):
        dec = []
        enc = base64.urlsafe_b64decode(enc)
        for i in range(len(enc)):
            key_c = key[i % len(key)]
            dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
            dec.append(dec_c)
        return "".join(dec)

    def connection(self):
        cons=config.get('dk.aarhuskommune.odaa_url')
        result={}
        upsd=cons.split("/")
        ups=upsd[2].split(":")
        result["user"]=ups[0]
        ps=ups[1].split("@")
        result["password"]=ps[0]
        result["host"]=ps[1]
        result["database"]=upsd[3]
        return result

    def emailNotifikation(self,context):   
        result=self.connection()           
        connectString = """dbname='%s' user='%s' host='%s' password='%s'""" % (result["database"],result["user"],result["host"],result["password"])
        conn = psycopg2.connect(connectString)
        c = conn.cursor()                     
        now = datetime.datetime.now()        
        date=now.strftime('%Y/%m/%d %H:%M:%S')
        sql="SELECT * FROM mailnotifikation where _guid='%s' and registered='False';" % request.params.get('guid', 'Not present').encode('utf-8')
        c.execute(sql)
        rows=c.fetchall()   
        if len(rows)>0:
            password=self._decode(result["password"], rows[0][5])
            data_dict={'name': rows[0][2], 'email': rows[0][4], 'fullname': rows[0][3],'password1':password,'password2':password}
            sql="UPDATE mailnotifikation SET registered='True' WHERE _guid='%s';" % request.params.get('guid', 'Not present').encode('utf-8')
    	    c.execute(sql)
            conn.commit()
            conn.close()
            self._save_new(context,data_dict)            

    def send_mail(self,to,subject, _body):              
        body = _body.replace('\n', '\r\n')
        guid=str(uuid.uuid4())
        body = config.get('ckan.site_url') + "/user/register?guid=" + guid + "&activate"
        # Prepare actual message
        message = """From: %s
        To: %s
        Subject: %s

        %s 
        """ % (config.get('dk.aarhuskommune.odaa_from'),str(to),subject,body)

        try:
            result=self.connection()       
            connectString = """dbname='%s' user='%s' host='%s' password='%s'""" % (result["database"],result["user"],result["host"],result["password"])
            conn = psycopg2.connect(connectString)
            c = conn.cursor()            
            p=request.params["password1"]            
            password=self._encode(result["password"],p)
            now = datetime.datetime.now()                                    
            sql="INSERT INTO mailnotifikation VALUES ('" + guid + "','" + str(now) + "','" + request.params["name"] + "','" +request.params["fullname"] +   "','" + request.params["email"] + "','" + password + "','False')"
            c.execute(sql)
	    conn.commit()

            nowlm = now - datetime.timedelta(days=int(config.get('dk.aarhuskommune.odaa_days')))
            sNowlm=nowlm.strftime('%Y-%m-%d')            
            sql="delete from mailnotifikation where _date<'%s'" % (sNowlm);           
            c.execute(sql)
	    conn.commit()
            conn.close()
            smtpObj = smtplib.SMTP('localhost')        
            to=to.split(',')
            smtpObj.sendmail(config.get('dk.aarhuskommune.odaa_from'), to, message)
        except Exception as e:
            logging.error('Error: unable to send email. %s ',e)
            #sys.exit(1)

    def register(self, data=None, errors=None, error_summary=None):
        context = {'model': model, 'session': model.Session, 'user': c.user,
                   'auth_user_obj': c.userobj}
        try:            
            check_access('user_create', context)
        except NotAuthorized,e:
            abort(401, _('Unauthorized to register as a user.'))        
        return self.new(data, errors, error_summary)

    def new(self, data=None, errors=None, error_summary=None):
        '''GET to display a form for registering a new user.
           or POST the form data to actually do the user registration.
        '''
        context = {'model': model, 'session': model.Session,
                   'user': c.user or c.author,
                   'auth_user_obj': c.userobj,
                   'schema': self._new_form_to_db_schema(),
                   'save': 'save' in request.params,
                   'activate':'activate' in request.params}

        try:
            check_access('user_create', context)            
        except NotAuthorized:
            abort(401, _('Unauthorized to create a user'))
        if context['save'] and not data:            
            return self._send_mail(context)
        if context['activate'] and not data:          
            self.emailNotifikation(context)                      
        if c.user and not data:
            # #1799 Don't offer the registration form if already logged in
            return render('user/logout_first.html')
        data = data or {}
        errors = errors or {}
        error_summary = error_summary or {}
        vars = {'data': data, 'errors': errors, 'error_summary': error_summary}

        c.is_sysadmin = new_authz.is_sysadmin(c.user)
        c.form = render(self.new_user_form, extra_vars=vars)
        return render('user/new.html')

    def _send_mail(self, context):
        data_dict = logic.clean_dict(unflatten(logic.tuplize_dict(logic.parse_params(request.params))))     
        error_summary={}
        errors={}
        if str(request.params["password1"])=='':
            error_summary["Password"]="Please enter both passwords"
        if str(request.params["password2"])=='':
            error_summary["Password"]="Please enter both passwords"
        if str(request.params["password1"])!=str(request.params["password2"]):
            error_summary["Password"]="The passwords you entered do not match"
        if str(request.params["name"])=='':
            error_summary["Name"]="Missing value"            
        if str(request.params["email"])=='':
            error_summary["Email"]="Missing value"        
        else:
            if not re.match(r"[^@]+@[^@]+\.[^@]+", request.params["email"]):
                error_summary["Email"]="Email is not valid"
        if error_summary!={}:
            return self.new(data_dict, errors, error_summary)
        email=request.params['email']
        self.send_mail(self,email,"Email vertifikation")
        return render('user/reciveMail.html')
       
    def _save_new(self, context,data_dict):
        try:
            context['message'] = data_dict.get('log_message', '')
            captcha.check_recaptcha(request)
            user = get_action('user_create')(context, data_dict)
        except NotAuthorized:
            abort(401, _('Unauthorized to create user %s') % '')
        except NotFound, e:
            abort(404, _('User not found'))
        except DataError:
            abort(400, _(u'Integrity Error'))
        except captcha.CaptchaError:
            error_msg = _(u'Bad Captcha. Please try again.')
            h.flash_error(error_msg)
            return self.new(data_dict)
        except ValidationError, e:
            errors = e.error_dict
            error_summary = e.error_summary
            return self.new(data_dict, errors, error_summary)
        if not c.user:
            # log the user in programatically
            rememberer = request.environ['repoze.who.plugins']['friendlyform']
            identity = {'repoze.who.userid': data_dict['name']}
            response.headerlist += rememberer.remember(request.environ,
                                                       identity)
            h.redirect_to(controller='user', action='me', __ckan_no_root=True)
        else:
            # #1799 User has managed to register whilst logged in - warn user
            # they are not re-logged in as new user.
            h.flash_success(_('User "%s" is now registered but you are still '
                            'logged in as "%s" from before') %
                            (data_dict['name'], c.user))
            return render('user/logout_first.html')

