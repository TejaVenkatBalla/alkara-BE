"""
file_upload view
"""
import pandas as pd
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializers import UploadSerializer
from .models import Tickets
# from .permissions import UserRolePermission


class FileUploadView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser,)
    # permission_classes = [UserRolePermission]
    # required_role = ['Admin', 'Coordinator']

    def post(self, request, *args, **kwargs):
        try:
            file = request.data['file']
            if file.name.endswith('.csv'):
                df = pd.read_csv(file)
            elif file.name.endswith(('.xls', '.xlsx')):
                df = pd.read_excel(file)
            else:
                return Response({'error': 'Unsupported file format'})

            # Assuming the columns in the DataFrame match the model fields
            records = df.to_dict(orient='records')
            modified_records = []
            for record in records:
                new_record = {
                    "customer_name": record.get('full_name'),
                    "primary_number": record.get('phone_number'),
                    "address": record.get('city'),
                    "email": record.get('email'),
                    "campaign_name": record.get('campaign_name'),
                    "source": record.get("source","")
                }
                file_serializer = UploadSerializer(data=new_record)
                if file_serializer.is_valid():
                    modified_records.append(new_record)
                    Tickets.objects.create(**new_record)
                    
                else:
                    return Response(file_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            return Response({'message': 'Data inserted successfully'}, status=status.HTTP_200_OK)
        except Exception as err:
            return Response({'message': f'Data insertion failed - {err}'}, status=status.HTTP_400_BAD_REQUEST)
