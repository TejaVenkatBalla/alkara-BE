from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, User
from alkara.base_model import BaseModel
from django.conf import settings


class CustomUserManager(BaseUserManager):
    def create_user(self, email=None, password=None, **extra_fields):
        # if not email:
        #     raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)




class Category(BaseModel):
    """
    Category Model
    """
    name = models.CharField(max_length=50)
    is_active = models.BooleanField(default=True)


class Product(BaseModel):
    """
    Product Model
    """
    name = models.CharField(max_length=100)
    price = models.FloatField()
    category = models.ForeignKey(Category, on_delete=models.CASCADE, null=False)
    is_active = models.BooleanField(default=True)


class Customer(BaseModel):
    """
    Customer Model
    """
    name = models.CharField(max_length=50)
    primary_phone = models.CharField(max_length=15)
    is_active = models.BooleanField(default=True)
    email = models.CharField(max_length=50)


class Address(BaseModel):
    """
    Address Model
    """
    address = models.CharField(max_length=255, null=True)
    state = models.CharField(max_length=50, null=True)
    district = models.CharField(max_length=50, null=True)
    city = models.CharField(max_length=50, null=True)
    pincode = models.IntegerField(null=True)
    is_active = models.BooleanField(default=True)
    is_primary = models.BooleanField(default=False)
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, null=True)


class Tickets(BaseModel):
    """
    TIcket Model
    """
    customer_name = models.CharField(max_length=50)
    primary_number = models.CharField(max_length=15)
    address = models.CharField(max_length=255)
    pincode = models.IntegerField(default=000000, null=True)
    state = models.CharField(max_length=100, null=True)
    email = models.CharField(max_length=100, null = True)
    schedule = models.CharField(max_length=100, null=True)
    assignee = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    product = models.ForeignKey(Product, on_delete=models.CASCADE, null=True, blank=True)
    estimate = models.FloatField(null=True)
    source = models.CharField(max_length=50, null=True, blank=True)
    campaign_name = models.CharField(max_length=100, null=True, blank=True)


class Roles(BaseModel):
    """
    User Roles
    """
    name = models.CharField(max_length=25)


class UserRoleMapping(BaseModel):
    """"
    UserRoleMapping model
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=False)
    role = models.ForeignKey(Roles, on_delete=models.CASCADE, null=False)
    is_active = models.BooleanField(default=True)


class TicketConversation(BaseModel):
    """
    This module maintains ticket conversation.
    """
    ticket = models.ForeignKey(Tickets, on_delete=models.CASCADE, null=False)
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=False, related_name="sender")
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, related_name="recipient")
    content = models.CharField(max_length=255, null=True, blank=True)

class CustomUser(AbstractBaseUser):

    username = models.CharField(max_length=150,unique=True,blank=True)
    email = models.EmailField(default=None)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    address =models.ForeignKey(Address,on_delete=models.CASCADE,null=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email