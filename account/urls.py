from django.urls import path, include

from account.views import UserRegistrationView, UserLoginView, UserDetailsView, UserChangePasswordView, \
    UserEditDetailsView, GetAllUsersView, DeleteUserView

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('userdetails/', UserDetailsView.as_view(), name='userdetails'),
    path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),
    path('edituser', UserEditDetailsView.as_view(), name='edituser'),
    path('allusers', GetAllUsersView.as_view(), name='allusers'),
    path('del-user/<int:pk>/', DeleteUserView.as_view(), name='delete-user'),
]
