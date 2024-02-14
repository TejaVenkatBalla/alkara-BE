"""
Views
# """
import json
from datetime import datetime
from django.utils import timezone
from rest_framework import filters
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from rest_framework import generics
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.pagination import PageNumberPagination
from django_filters.rest_framework import DjangoFilterBackend
from .serializers import UserSerializer, UserListSerializer
from django.contrib.auth.models import User
from .models import Category, Product, Address, Customer, Tickets, Roles, TicketConversation, UserRoleMapping
from .serializers import CategorySerializer, ProductSerializer, AddressSerializer, CustomerSerializer, TicketsSerializer, RolesSerializer, TicketConversationListSerializer, UserRoleMappingSerializer, TicketConversationCreateSerializer
# from .permissions import UserRolePermission
from django.db.models import Q
from django.contrib.auth import get_user_model
User=get_user_model()

filters_list = ["exact", "iexact", "in", "lt", "lte", "isnull", \
                "gt", "gte", "range", "istartswith", "iendswith", "icontains"]

def getListData(instance):
    """
    This is a common function for all listing api's to fetch the data.
    """
    try:
        queryset = instance.get_queryset()
        queryset = instance.filter_queryset(queryset)
        page = instance.paginate_queryset(queryset)
        if page:
            serializer = instance.get_serializer(page, many=True)
            return instance.get_paginated_response(serializer.data)
        serializer = instance.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Exception as err:
        return Response({"error":str(err)}, status=status.HTTP_400_BAD_REQUEST)


class CustomPagination(PageNumberPagination):
    """Custom pagination class.

    This class defines a custom pagination behavior, allowing clients to control the page size
    using the 'page_size_query_param' parameter.

    Attributes:
        page_size_query_param (str): The query parameter used for specifying the page size.

    """
    page_size_query_param = 'page_size'


def serialize_datetime(obj):
    """
    Serialize login response
    """
    if isinstance(obj, datetime):
        return obj.isoformat()


class CustomAuthToken(ObtainAuthToken):
    """
    Login APi
    """
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        if user:
            user.last_login = timezone.now()
            user.save()
        json_data = json.dumps(user.__dict__, default=serialize_datetime)
        user_object = json.loads(json_data)
        user_object.pop("password")
        user_object.pop("backend")
        user_object.pop("_state")
        role = UserRoleMapping.objects.filter(user_id=user.id).first()
        user_object['role'] = role.role.name
        return Response({'token': token.key, 'user': user_object},
                        status=status.HTTP_200_OK)


class LogoutView(APIView):
    """
    LogoutView
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """
        This function will clear the user session from the DB.
        """
        request.auth.delete()
        return Response({'detail': 'Logout successful'}, status=status.HTTP_200_OK)


@csrf_exempt
@api_view(['POST'])
def perform_signup(request):
    """
    This route creates a user into the application
    """
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserListView(generics.ListAPIView):
    """
    UserListView
    """
    queryset = User.objects.all()
    serializer_class = UserListSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]

    filterset_fields = {
        'id': filters_list,
        'username': filters_list,
        'last_login': filters_list
    }
    ordering_fields = ['id', 'username', 'last_login']

    ordering = ['id']
    pagination_class = CustomPagination

    def list(self, request, *args, **kwargs):
        """
        Customized list method to add extra information or modify the response.
        """
        return getListData(self)


class CategoryListCreateView(generics.ListCreateAPIView):
    """
    CategoryListCreateView
    """
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]

    filterset_fields = {
        'id': filters_list,
        'name': filters_list,
        'is_active': filters_list,
        'created_at': filters_list,
        'updated_at':filters_list,
        'deleted_at': filters_list
    }
    ordering_fields = ['id', 'name', 'is_active', 'created_at', 'updated_at', 'deleted_at']

    ordering = ['id']
    pagination_class = CustomPagination

    def list(self, request, *args, **kwargs):
        """
        Customized list method to add extra information or modify the response.
        """
        queryset = self.get_queryset()
        queryset = self.filter_queryset(queryset)
        page = self.paginate_queryset(queryset)
        if page:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class CategoryDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    CategoryDetailView
    """
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]


class ProductListCreateView(generics.ListCreateAPIView):
    """
    ProductListCreateView
    """
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]

    filterset_fields = {
        'id': filters_list,
        'name': filters_list,
        'price': filters_list,
        'is_active': filters_list,
        'created_at': filters_list,
        'updated_at':filters_list,
        'deleted_at': filters_list
    }
    ordering_fields = ['id', 'name', 'price', 'is_active', 'created_at', 'updated_at', 'deleted_at']

    ordering = ['id']
    pagination_class = CustomPagination

    def list(self, request, *args, **kwargs):
        """
        Customized list method to add extra information or modify the response.
        """
        queryset = self.get_queryset()
        queryset = self.filter_queryset(queryset)
        page = self.paginate_queryset(queryset)
        if page:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ProductDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    ProductDetailView
    """
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]


class AddressListCreateView(generics.ListCreateAPIView):
    """
    AddressListCreateView
    """
    queryset = Address.objects.all()
    serializer_class = AddressSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request, *args, **kwargs):
        """
        Customized list method to add extra information or modify the response.
        """
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AddressDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    AddressDetailView
    """
    queryset = Address.objects.all()
    serializer_class = AddressSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]


class CustomerListCreateView(generics.ListCreateAPIView):
    """
    CustomerListCreateView
    """
    queryset = Customer.objects.all()
    serializer_class = CustomerSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request, *args, **kwargs):
        """
        Customized list method to add extra information or modify the response.
        """
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class CustomerDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    CustomerDetailView
    """
    queryset = Customer.objects.all()
    serializer_class = CustomerSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]


class TicketsListCreateView(generics.ListCreateAPIView):
    """
    TicketsListCreateView
    """
    # permission_classes = [UserRolePermission]
    # required_role = 'Executor'
    # queryset = Tickets.objects.all()
    serializer_class = TicketsSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]

    filterset_fields = {
        'id': filters_list,
        'customer_name': filters_list,
        'created_at': filters_list,
        'updated_at':filters_list,
        'deleted_at': filters_list
    }
    ordering_fields = ['id', 'customer_name', 'created_at', 'updated_at', 'deleted_at']

    ordering = ['-created_at']
    pagination_class = CustomPagination

    def list(self, request, *args, **kwargs):
        """
        Customized list method to add extra information or modify the response.
        """
        logged_in_user = request.user.id
        print(f"logged_in_user-{logged_in_user}")
        # queryset = Tickets.objects.filter(assignee=logged_in_user).all()
        self.queryset = Tickets.objects.all()
        return getListData(self)

    def create(self, request, *args, **kwargs):
        """
        Customized create method to add extra logic or modify the response.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class TicketsDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    TicketsDetailView
    """
    queryset = Tickets.objects.all()
    serializer_class = TicketsSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]


class TicketAssignmentView(APIView):
    """
    Assign/ReAssign view
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, ticket_id):
        """
        Assign/ReAssign route
        """
        try:
            data = request.data
            if not data.get("assigned_to"):
                raise Exception("Missing mandatory field - assigned_to")
            ticket = Tickets.objects.get(pk=int(ticket_id))
            assignee = User.objects.get(pk=data.get("assigned_to"))
            if ticket:
                ticket.assignee = assignee
                ticket.save()
            return Response({"message": "Success"}, status=status.HTTP_200_OK)
        except Exception as err:
            return Response({"message": str(err)}, status=status.HTTP_400_BAD_REQUEST)


class TicketConversationView(generics.ListCreateAPIView):
    """
    Ticket Conversation
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]

    filterset_fields = {
        'id': filters_list,
        'sender': filters_list,
        'content': filters_list,
        'created_at': filters_list,
        'updated_at':filters_list,
        'deleted_at': filters_list
    }
    ordering_fields = ['id', 'sender', 'content', 'created_at', 'updated_at', 'deleted_at']

    ordering = ['id']
    pagination_class = CustomPagination

    def get_serializer_class(self):
        """
        Determine serializer class based on request method.
        """
        if self.request.method == 'GET':
            return TicketConversationListSerializer
        return TicketConversationCreateSerializer

    def list(self, request, ticket_id, *args, **kwargs):
        """
        Customized list method to add extra information or modify the response.
        """
        queryset = TicketConversation.objects.filter(ticket=ticket_id).all()
        queryset = self.filter_queryset(queryset)
        page = self.paginate_queryset(queryset)
        if page:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def create(self, request, ticket_id, *args, **kwargs):
        """
        Customized create method to add extra logic or modify the response.
        """
        data = request.data
        user_id = request.user.id
        ticket = Tickets.objects.get(pk=ticket_id)
        sender = User.objects.get(pk=user_id)
        data_obj = {
            'ticket': ticket.id,
            'sender': sender.id,
            'content': data.get("content")
            }
        serializer = self.get_serializer(data=data_obj)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class RoleListCreateView(generics.ListCreateAPIView):
    """
    CustomerListCreateView
    """
    queryset = Roles.objects.all()
    serializer_class = RolesSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request, *args, **kwargs):
        """
        Customized list method to add extra information or modify the response.
        """
        return getListData(self)


class RoleDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    CustomerDetailView
    """
    queryset = Roles.objects.all()
    serializer_class = RolesSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]


class RoleAssignView(generics.ListCreateAPIView):
    """
    Assign role to user
    """
    queryset = UserRoleMapping.objects.all()
    serializer_class = UserRoleMappingSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        """
        Customized create method to add extra logic or modify the response.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

from .serializers import CustomUserSerializer2

@api_view(['GET',])
def get_cood(request):
    """
    This method for
    """
    try:
        username = request.GET.get("username")
        user=User.objects.get(username=username)
        user_address =user.address
        role = Roles.objects.filter(userrolemapping__user=user, userrolemapping__is_active=True).first()
        print(role.name)
        if role.name =="Coordinator" or role.name=="Admin":
            users = User.objects.filter(
                    Q(address=user_address) &  # Filter by the same address
                    Q(userrolemapping__role__name='Executor')  # Filter by role name 'Executor'
                )

            #users = User.objects.filter(address=user_address).exclude(pk=user.pk)

            x=CustomUserSerializer2(users,many=True)
        
            return Response(x.data)
        else:
            return Response("the user's role is not Coordinator or Admin")


    except Exception as err:
        raise err