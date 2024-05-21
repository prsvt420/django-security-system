from django.urls import path

from security_system import views

app_name = 'security_system'

urlpatterns = [
    path('logs/', views.security_system_logs, name='logs'),
]
