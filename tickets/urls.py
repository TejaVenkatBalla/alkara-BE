from django.urls import path
from .views import perform_signup, CustomAuthToken, UserListView, CategoryListCreateView, CategoryDetailView, ProductListCreateView, ProductDetailView, AddressListCreateView, AddressDetailView, CustomerListCreateView, CustomerDetailView, TicketsListCreateView, TicketsDetailView, LogoutView, RoleListCreateView, RoleDetailView, TicketAssignmentView, TicketConversationView, RoleAssignView
from .fileupload_view import FileUploadView
from tickets import views

urlpatterns = [
    path('login/', CustomAuthToken.as_view(), name='api_token_auth'),
    path('signup/', perform_signup, name='perform_signup'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path ('users/', UserListView.as_view(), name='UserListView'),

    path('categories/', CategoryListCreateView.as_view(), name='category-list-create'),
    path('categories/<int:pk>/', CategoryDetailView.as_view(), name='category-detail'),

    path('products/', ProductListCreateView.as_view(), name='product-list-create'),
    path('products/<int:pk>/', ProductDetailView.as_view(), name='product-detail'),

    path('addresses/', AddressListCreateView.as_view(), name='address-list-create'),
    path('addresses/<int:pk>/', AddressDetailView.as_view(), name='address-detail'),

    path('customers/', CustomerListCreateView.as_view(), name='customer-list-create'),
    path('customers/<int:pk>/', CustomerDetailView.as_view(), name='customer-detail'),

    path('tickets/', TicketsListCreateView.as_view(), name='tickets-list-create'),
    path('tickets/<int:pk>/', TicketsDetailView.as_view(), name='tickets-detail'),
    path('tickets/assign/<int:ticket_id>/', TicketAssignmentView.as_view(), name="ticket-assign-or-reassign"),
    path('tickets/chat/<int:ticket_id>/', TicketConversationView.as_view(), name='ticket-conversation'),

    path('roles/', RoleListCreateView.as_view(), name='roles-list-create'),
    path('roles/<int:pk>/', RoleDetailView.as_view(), name='roles-detail'),
    path('role/assign/', RoleAssignView.as_view(), name='Assign-role'),

    path('upload/', FileUploadView.as_view(), name="file_upload"),

    path('sam/', views.get_cood)
]
