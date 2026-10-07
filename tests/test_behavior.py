from common.app_response import AppResponse
from common.app_constants import AppConstants

def test_default_response_reports_failure():
    response = AppResponse()
    assert response['code'] == AppConstants.UNSUCCESSFULL_STATUS_CODE
    assert response['status'] is False
    assert response['message'] == 'failed'

def test_response_update_replaces_all_fields():
    response = AppResponse()
    response.set_response('200', {'id':7}, 'saved', True)
    assert response == {'code':'200','data':{'id':7},'message':'saved','status':True}

def test_explicit_response_preserves_empty_payload():
    assert AppResponse('200', [], 'no results', True)['data'] == []
