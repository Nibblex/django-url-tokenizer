from rest_framework import generics
from rest_framework.permissions import AllowAny

from .serializers import SendTokenSerializer, CheckTokenSerializer


class SendTokenView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = SendTokenSerializer


class CheckTokenView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = CheckTokenSerializer
