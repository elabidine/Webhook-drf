from rest_framework.views import APIView
from rest_framework.decorators import parser_classes
from rest_framework.parsers import JSONParser

from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status

from myproject import settings
import hmac,hashlib,base64
from rest_framework.permissions import AllowAny



class WebhookTest(APIView):
    parser_classes = [JSONParser]
    permission_classes = [AllowAny]
    def verifySignatur(self,receivedSignature,payload):
        webhooke_secret = settings.TYPEFORM_CLIENT_SECRET
        
        print("========",receivedSignature,payload)
        
        digest = hmac.new(webhooke_secret.encode('utf-8'),payload.encode('utf-8'),hashlib.sha256).digest()
        e = base64.b64encode(digest).decode()
        if e == receivedSignature:
            return True
        else:
            return False
        
    @csrf_exempt
    def post(self,request,*args,**kwargs):
        receivedSignature = request.headers.get("typeform_signature")
        if receivedSignature is None:
            return Response(
                {"Fail":"Permission denied"},
                status=status.HTTP_403_FORBIDDEN
            )
        sha_name,signature = receivedSignature.split("=",1)
        if sha_name != "sha256":
            return Response(
                {"Fail":"Invalid signature"},
                status=status.HTTP_501_NOT_IMPLEMENTED)
        raw_body = request.body.decode('utf-8')
        is_valid = self.verifySignatur(signature,raw_body)
        if is_valid != True:
            return Response(
                {"Fail":"Invalid signature. Permission denied"},
                status=status.HTTP_403_FORBIDDEN
            )
        return Response({},status=status.HTTP_200_OK)
