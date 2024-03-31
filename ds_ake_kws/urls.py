from django.urls import path
from .views import (
    upload_file,
    success,
    user_login,
    user_logout,
    file_search,
    signup,
    dashboard,
    download_file,
    error_page,
)
from django.conf.urls import handler404, handler500

urlpatterns = [
    path("upload/", upload_file, name="upload_file"),
    path("success/", success, name="success"),
    path("login/", user_login, name="login"),
    path("logout/", user_logout, name="logout"),
    path("upload/", upload_file, name="upload_file"),
    path("search/", file_search, name="file_search"),
    path("signup/", signup, name="signup"),
    path("dashboard/", dashboard, name="dashboard"),
    path("error/", error_page, name="error_page"),
    path('download/<int:file_id>/', download_file, name='download_file'),

]
handler404 = 'ds_ake_kws.views.error_page'
handler500 = 'ds_ake_kws.views.error_page'
