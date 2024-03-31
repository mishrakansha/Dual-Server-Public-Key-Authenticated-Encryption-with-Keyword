from django.shortcuts import render, redirect
from .forms import FileUploadForm
from .encryption import encrypt_file, decrypt_file, generate_key_pair, checkCode
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login, logout
from .forms import SignUpForm
from .models import EncryptedFile
import secrets
from django.contrib import messages
from django.db.models import Q
import logging
from django.http import HttpResponseServerError, HttpResponse, HttpResponseNotFound, FileResponse
from mimetypes import guess_type
import io

logger = logging.getLogger(__name__)

orgFile = ""


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
                # file_content = b""
                # for chunk in request.FILES["file"].chunks():
                #     file_content += chunk
                global orgFile
                orgFile = request.FILES["file"].read()
                private_key, public_key = generate_key_pair()
                encrypted_file_content, encrypted_symmetric_key = encrypt_file(
                    request.FILES["file"].read(), public_key
                )

                # checkCode(request.FILES["file"].read())
                encrypted_file = EncryptedFile(
                    owner=request.user,
                    encrypted_content=encrypted_file_content,
                    encrypted_symmetric_key=encrypted_symmetric_key,
                    name=request.FILES["file"].name,
                    private_key=private_key,
                    content=request.FILES["file"].read(),
                )
                decrypted_file_content = decrypt_file(
                    encrypted_file_content, encrypted_symmetric_key, private_key
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
    try:
        # Retrieve encrypted file object
        encrypted_file = EncryptedFile.objects.get(id=file_id)

        # Decrypt file content
        decrypted_content = decrypt_file(
            encrypted_file.encrypted_content,
            encrypted_file.encrypted_symmetric_key,
            encrypted_file.private_key,
        )
        # Determine MIME type
        file_obj = io.BytesIO(decrypted_content)

        print("orgFile.........", encrypted_file.content == decrypted_content,file_obj)
        mime_type, _ = guess_type(encrypted_file.name)
        if not mime_type:
            mime_type = "application/octet-stream"

        # Set up response
        response = FileResponse(file_obj, content_type=mime_type)
        response["Content-Disposition"] = (
            f'attachment; filename="{encrypted_file.name}"'
        )

        return response

    except EncryptedFile.DoesNotExist:
        return HttpResponseNotFound("File not found")

    except Exception as e:
        return HttpResponseServerError(f"An error occurred: {str(e)}")


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
