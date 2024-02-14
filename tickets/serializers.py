"""
serializers module
"""
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import CustomUser, Category, Product, Address, Customer, Tickets, Roles, TicketConversation, UserRoleMapping
from django.contrib.auth import get_user_model
User=get_user_model()

class UserSerializer(serializers.ModelSerializer):
    """
    UserSerializer
    """
    class Meta:
        """
        Meta
        """
        model = User
        fields = ['username', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        """
        Create Serializer
        """
        user = User.objects.create_user(**validated_data)
        return user


class UserListSerializer(serializers.ModelSerializer):
    """
    UserListSerializer
    """
    role = serializers.SerializerMethodField()

    def get_role(self, obj):
        """
        This methods returns the user role.
        """
        # if obj.id:
        #     return UserRoleMapping.objects.filter(user=obj.id).first().role.name
        # return None
        user_role_mapping = UserRoleMapping.objects.filter(user=obj.id).first()
        if user_role_mapping:
            return user_role_mapping.role.name
        return None

    class Meta:
        """
        Meta
        """
        model = User
        exclude = ('password',)


class CustomUserSerializer(serializers.ModelSerializer):
    """
    CustomUserSerializer
    """
    class Meta:
        """
        Meta
        """
        model = CustomUser
        fields = ('id', 'email', 'first_name', 'last_name', 'is_active', 'is_staff')


class CategorySerializer(serializers.ModelSerializer):
    """
    CategorySerializer
    """
    class Meta:
        """
        Meta
        """
        model = Category
        fields = '__all__'


class ProductSerializer(serializers.ModelSerializer):
    """
    ProductSerializer
    """
    class Meta:
        """
        Meta
        """
        model = Product
        fields = '__all__'


class AddressSerializer(serializers.ModelSerializer):
    """
    AddressSerializer
    """
    class Meta:
        """
        Meta
        """
        model = Address
        fields = '__all__'


class CustomerSerializer(serializers.ModelSerializer):
    """
    CustomerSerializer
    """
    class Meta:
        """
        Meta
        """
        model = Customer
        fields = '__all__'

class TicketsSerializer(serializers.ModelSerializer):
    """
    TicketsSerializer
    """
    class Meta:
        """
        Meta
        """
        model = Tickets
        fields = '__all__'


class TicketConversationCreateSerializer(serializers.ModelSerializer):
    """
    TicketConversationCreateSerializer
    """
    class Meta:
        """
        Meta
        """
        model = TicketConversation
        fields = '__all__'


class TicketConversationListSerializer(serializers.ModelSerializer):
    """"
    TicketConversationListSerializer
    """
    sender = serializers.SerializerMethodField()
    role = serializers.SerializerMethodField()
    def get_sender(self, obj):
        """
            This method takes an object with a related sender and returns sender username
            containing relevant client information, such as the sender's name.
        """
        if obj.sender:
            return obj.sender.username
        return None

    def get_role(self, obj):
        """
        This methods returns the sender role.
        """
        if obj.sender:
            return UserRoleMapping.objects.filter(user=obj.sender.id).first().role.name
        return None

    class Meta:
        """
        Meta
        """
        model = TicketConversation
        fields = '__all__'


class RolesSerializer(serializers.ModelSerializer):
    """
    RolesSerializer
    """
    class Meta:
        """
        Meta
        """
        model = Roles
        fields = '__all__'


class UploadSerializer(serializers.ModelSerializer):
    """
    UploadSerializer
    """
    class Meta:
        """
        Meta
        """
        model = Tickets
        fields = '__all__'


class UserRoleMappingSerializer(serializers.ModelSerializer):
    """"
    UserRoleMappingSerializer
    """
    class Meta:
        """
        Meta
        """
        model = UserRoleMapping
        fields = '__all__'


from rest_framework import serializers
from .models import CustomUser

class AddressSerializer2(serializers.ModelSerializer):
    class Meta:
        model = Address
        fields = ['state']

class CustomUserSerializer2(serializers.ModelSerializer):
    address = AddressSerializer2()

    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_active', 'is_staff', 'address']