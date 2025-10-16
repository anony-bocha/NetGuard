from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('run-scan/', views.run_scan_view, name='run_scan'),
]
