from django.shortcuts import render, redirect
from .forms import FileUploadForm
from .encryption import encrypt_file, decrypt_file, generate_key_pair
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login, logout
from .forms import SignUpForm
from .models import EncryptedFile
import secrets
from django.contrib import messages
from django.db.models import Q
import logging
from django.http import (
    HttpResponseServerError,
    HttpResponse,
    HttpResponseNotFound,
    FileResponse,
)
import io

import os
from django.conf import settings

logger = logging.getLogger(__name__)


def dashboard(request):
    if request.user.is_authenticated:
        uploaded_files = EncryptedFile.objects.filter(owner=request.user)
        context = {"uploaded_files": uploaded_files}
        return render(request, "dashboard.html", context)
    else:
        return redirect("login")


def signup(request):
    if request.method == "POST":
        form = SignUpForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("login")
    else:
        form = SignUpForm()
    return render(request, "signup.html", {"form": form})


def home(request):
    return render(request, "home.html")


def upload_file(request):
    if request.method == "POST":
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                uploaded_file = request.FILES["file"]
                original_file_content = uploaded_file.read()

                private_key, public_key = generate_key_pair()
                encrypted_file_content, encrypted_symmetric_key = encrypt_file(
                    original_file_content, public_key
                )

                encrypted_file = EncryptedFile(
                    owner=request.user,
                    encrypted_content=encrypted_file_content,
                    encrypted_symmetric_key=encrypted_symmetric_key,
                    name=uploaded_file.name,
                    private_key=private_key,
                    content=original_file_content,
                    file=uploaded_file,
                )

                encrypted_file.save()

                return render(
                    request,
                    "upload_file.html",
                    {
                        "form": form,
                        "messages": "File uploaded and encrypted successfully!",
                    },
                )

            except Exception as e:
                print(f"Error uploading file: {e}")
                messages.error(request, "An error occurred while uploading the file.")
                return HttpResponseServerError(
                    "An error occurred while uploading the file."
                )
    else:
        form = FileUploadForm()

    return render(request, "upload_file.html", {"form": form})


def download_file(request, file_id):
    encrypted_file = EncryptedFile.objects.get(id=file_id)
    decrypt_file(
        encrypted_file.encrypted_content,
        encrypted_file.encrypted_symmetric_key,
        encrypted_file.private_key,
    )
    response = HttpResponse(encrypted_file.file, content_type='application/octet-stream')
    response['Content-Disposition'] = f'attachment; filename="{encrypted_file.name}"'
    return response


def file_search(request):
    keyword = request.POST.get("keyword", "")
    if keyword:
        encrypted_files = EncryptedFile.objects.filter(name__icontains=keyword)
        decrypted_files = []
        for file in encrypted_files:

            decrypted_file = decrypt_file(
                file.encrypted_content, file.encrypted_symmetric_key, file.private_key
            )
            decrypted_file_info = {
                "id": file.id,
                "name": file.name,
                "content": decrypted_file,
            }
            decrypted_files.append(decrypted_file_info)
    else:
        decrypted_files = None
    return render(
        request, "file_search.html", {"files": decrypted_files, "keyword": keyword}
    )


def error_page(request, exception=None):
    error_message = request.session.pop("error_message", None)
    return render(request, "error_page.html", {"error_message": error_message})


def success(request):
    return render(request, "success.html")


def user_login(request):
    if request.method == "POST":
        form = AuthenticationForm(request, request.POST)
        if form.is_valid():
            login(request, form.get_user())
            return redirect("dashboard")
    else:
        form = AuthenticationForm()
    return render(request, "login.html", {"form": form})


@login_required
def user_logout(request):
    logout(request)
    return redirect("login")
