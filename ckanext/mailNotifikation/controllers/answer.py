import ckan.lib.base as base
import logging
from datetime import datetime
from ckan.common import _, c, request

log = logging.getLogger(__name__)

class AnswersController(base.BaseController):

    def index(self):        
        log.info("index")
        i = datetime.now()
        date=i.strftime('%Y/%m/%d %H:%M:%S')
        kommerFra=request.params.get('kommerFra', 'Not present').encode('utf-8')
        spg1=request.params.get('spg1', 'Not present').encode('utf-8')
        log.info("index:spg1=" + spg1)
