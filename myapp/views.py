#myapp views
from django.template import loader
from .models import To_do_list
from django.contrib.auth import authenticate, login as auth_login, logout
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.mail import EmailMessage, send_mail
from Things_To_Do import settings
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from .email_tokens import generate_token
from django.views import generic

from .authentication import create_access_token, create_refresh_token, decode_access_token, decode_refresh_token
from .authentication import  create_forget_password_token, decode_forget_password_token
from rest_framework.response import Response



#-------------------------------------------- SIGNUP
def signup(request):
    if request.method == "GET":
       return render(request, "authentication/signup.html")
    if request.method == "POST":
       #username = request.POST.get('username')
       username = request.POST['signup_username']
      #  firstname = request.POST['firstname']
      #  lastname = request.POST['lastname']
       email = request.POST['signup_email']
       password1 = request.POST['signup_password1']
       password2 = request.POST['signup_password2']

      #  username=username.lower()
       if User.objects.filter(username=username).exists():
          messages.warning(request, "Username already exist, Username must be unique.")
          return redirect('signup')
       if User.objects.filter(email=email).exists():
          messages.warning(request, "Email Already Registered!")
          return redirect('signup')
        
       if len(username)>20:
          messages.warning(request, "Username must be under 20 charcters!")
          return redirect('signup')
       
       if not username.isalnum():
          messages.warning(request, "Username must be Alpha-Numeric!")
          return redirect('signup')
       
       lower_username = username.lower()
       if not username == lower_username:
          messages.warning(request, "Username must be lower case!")
          return redirect('signup')
       
       if password1 != password2:
          messages.warning(request, "Password didn't matched!")
          return redirect('signup')
        


       myuser = User.objects.create_user(username, email, password1)
      #  myuser.first_name = firstname
      #  myuser.last_name = lastname
       myuser.is_active = False
       myuser.save()
       messages.success(request, "Your account has been created successfully.")
       

       # Welcome Email
       subject = "Welcome to Things To-do!"
       welcome_message = render_to_string('email_templets/welcome_email.html',{
          'username': myuser.username,
       })
       from_email = settings.EMAIL_HOST_USER
       welcome_user_email = [myuser.email]
       send_mail(subject, welcome_message, from_email, welcome_user_email, fail_silently=True)
      
       # Email Address Confirmation Email
       current_site = get_current_site(request)
       email_subject = "Confirm your Email Address"
       email_confirmation_message = render_to_string('email_templets/confirmation_email.html',{
          'domain': current_site.domain,
          'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
          'token': generate_token.make_token(myuser)
       })
       from_email = settings.EMAIL_HOST_USER
       email_confirmation_user_email = [myuser.email]
       email = EmailMessage(email_subject, email_confirmation_message, from_email, email_confirmation_user_email)
       email.fail_silently = True
       email.send()
       messages.success(request, "We have sent you a confirmation email, please confirm your email address.")
       return redirect("login")
    
    return render(request, "authentication/signup.html")

#-------------------------------------------- TERMS AND CONDITIONS
def terms_and_conditions(request):
   return render(request, "authentication/terms_and_conditions.html")

#-------------------------------------------- ACTIVATE
def activate(request,uidb64,token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid) #passkey = pk
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser,token):
        #if user is already active
        if(myuser.is_active):
          messages.success(request, "Your Account is already activated, You can login.")
          return redirect('login')
        
        #if user is not active then activate user
        myuser.is_active = True
        myuser.save()

        first_todo = To_do_list(uqid = myuser.username, to_do='Welcome to Things To-do.', isco=False, dele=False)
        first_todo.save()

        messages.success(request, "Your Account has been activated, You can login now.")
        return redirect('login')
    else:
        logout(request)
        messages.error(request, "Something went wrong.")
        return redirect('signup')

#-------------------------------------------- LOGIN
def login(request):
    if request.method == "GET":
       return render(request, "authentication/login.html")
    
    
    if request.method == 'POST':
       #username = request.POST['username']
       username_or_email = request.POST.get('username_or_email')
       password = request.POST.get('password1')

       #if entered data is username
       try:
            myuser = User.objects.get(username = username_or_email)
            username = myuser.username
            user = authenticate(request, username = username, password = password)
            # user exist and useraccount is activated
            if user is not None:
               auth_login(request, user)
               # messages.success(request, "You're successfully logged in.")
               user_username = user.username
               access_token = create_access_token(user_username)
               response = redirect("home")
               response.set_cookie(key='access_token', value=access_token, httponly=True)
            #  refresh_token = create_refresh_token(username)
            #  response.set_cookie(key='refresh_token', value=refresh_token, httponly=True)
               return response
            
            # password is wrong or useraccount is not activated or user doesn't exist 
            else:
               try:
                  myuser = User.objects.get(username = username)
                  useraccount_is_activated = myuser.is_active
                  if useraccount_is_activated == True:
                     messages.warning(request, "Incorrect username or password.")
                     return redirect('login')
                  if useraccount_is_activated == False:
                     # Email Address Confirmation Email
                     messages.warning(request, "Your account is not activated.")
                     current_site = get_current_site(request)
                     email_subject = "Confirm your Email Address"
                     email_confirmation_message = render_to_string('email_templets/confirmation_email.html',{
                        'domain': current_site.domain,
                        'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
                        'token': generate_token.make_token(myuser)
                     })
                     from_email = settings.EMAIL_HOST_USER
                     email_confirmation_user_email = [myuser.email]
                     email = EmailMessage(email_subject, email_confirmation_message, from_email, email_confirmation_user_email)
                     email.fail_silently = True
                     email.send()
                     messages.success(request, "We have sent you a confirmation email, please confirm your email address.")
                     return redirect("login")
               except:
                  logout(request)
                  messages.warning(request, "Incorrect username or password.")
                  return redirect('login')
       except:
            #if entered data is email
            try:
                  myuser = User.objects.get(email = username_or_email)
                  username = myuser.username
                  user = authenticate(request, username = username, password = password)
                  # user exist and useraccount is activated
                  if user is not None:
                     auth_login(request, user)
                     user_username = user.username
                     # messages.success(request, "You're successfully logged in.")
                     access_token = create_access_token(user_username)
                     response = redirect("home")
                     response.set_cookie(key='access_token', value=access_token, httponly=True)
                  #  refresh_token = create_refresh_token(username)
                  #  response.set_cookie(key='refresh_token', value=refresh_token, httponly=True)
                     return response
                  
                  # password is wrong or useraccount is not activated or user doesn't exist 
                  else:
                     try:
                        myuser = User.objects.get(username = username)
                        useraccount_is_activated = myuser.is_active
                        if useraccount_is_activated == True:
                           messages.warning(request, "Incorrect username or password.")
                           return redirect('login')
                        if useraccount_is_activated == False:
                           # Email Address Confirmation Email
                           messages.warning(request, "Your account is not activated.")
                           current_site = get_current_site(request)
                           email_subject = "Confirm your Email Address"
                           email_confirmation_message = render_to_string('email_templets/confirmation_email.html',{
                              'domain': current_site.domain,
                              'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
                              'token': generate_token.make_token(myuser)
                           })
                           from_email = settings.EMAIL_HOST_USER
                           email_confirmation_user_email = [myuser.email]
                           email = EmailMessage(email_subject, email_confirmation_message, from_email, email_confirmation_user_email)
                           email.fail_silently = True
                           email.send()
                           messages.success(request, "We have sent you a confirmation email, please confirm your email address.")
                           return redirect("login")
                     except:
                        logout(request)
                        messages.warning(request, "Incorrect username or password.")
                        return redirect('login')
            except:
                  logout(request)
                  messages.warning(request, "Incorrect username or password.")
                  return render(request, "authentication/login.html")

    return render(request, "authentication/login.html")

#-------------------------------------------- FORGET PASSWORD
def forget_password_email(request):
    if request.method == "GET":
       return render(request, "authentication/forget_password.html")
    
    if request.method == 'POST':
       user_email = request.POST.get('forget_email')
       print(user_email)

       try:
            myuser = User.objects.get(email = user_email)
            useraccount_is_activated = myuser.is_active
            print(myuser)
            print(useraccount_is_activated)

            #if user is activated
            if useraccount_is_activated == True:
               print(1)
               current_site = get_current_site(request)
               print(2)
               email_subject = "Things To-do - Forget Password"
               email_confirmation_message = render_to_string('email_templets/forget_password_email.html',{
                  'domain': current_site.domain,
                  'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
                  'token': create_forget_password_token(myuser.username),
               })
               print(3)
               from_email = settings.EMAIL_HOST_USER
               print(4)
               email_confirmation_user_email = [myuser.email]
               print(5)
               email = EmailMessage(email_subject, email_confirmation_message, from_email, email_confirmation_user_email)
               print(6)
               email.fail_silently = True
               print(7)
               email.send()
               print(8)
               messages.success(request, "We have successfully sent you an email to reset your password, please open it and set a new password.")
               print(9)
               return redirect("login")
            else:
               messages.warning(request, "Your account is not activated, Please activate it.")
               return redirect('login')
       except:
               messages.error(request, "Email address does not exist.")
               return redirect('signup')

    return render(request, "authentication/forget_password.html")

#-------------------------------------------- NEW PASSWORD
def new_password(request,uidb64,token):
    if request.method == "GET":
      try:
         uid = force_str(urlsafe_base64_decode(uidb64))
         myuser = User.objects.get(pk=uid) #passkey = pk
         decode_token_username = decode_forget_password_token(token)
         token_myuser = User.objects.get(username = decode_token_username)
         token_username = token_myuser.username
         username = myuser.username
      except (TypeError, ValueError, OverflowError, User.DoesNotExist, KeyError,):
         myuser = None
      
      if myuser is not None and token_username == username:
         data={
            "uidb64":uidb64,
            "token":token,
         }
         return render(request, "authentication/new_password.html", data)
      else:
         messages.error(request, "Something went wrong, invalid URL")
         return redirect('login')



    if request.method == 'POST':
      try:
         uid = force_str(urlsafe_base64_decode(uidb64))
         myuser = User.objects.get(pk=uid) #passkey = pk
         decode_token_username = decode_forget_password_token(token)
         token_myuser = User.objects.get(username = decode_token_username)
         token_username = token_myuser.username
         username = myuser.username
      except (TypeError, ValueError, OverflowError, User.DoesNotExist, KeyError,):
         myuser = None

      if myuser is not None and token_username == username:
         password1 = request.POST['password1']
         password2 = request.POST['password2']
         if password1 != password2:
            messages.warning(request, "Password didn't matched!")
            return redirect('login')
         else:
            myuser.set_password(password1)
            myuser.save()
            messages.success(request, "Password changed successfully.")
            return redirect('login')
      else:
         messages.error(request, "Something went wrong, invalid URL")
         return redirect('login')

    return render(request, "authentication/new_password.html")

#-------------------------------------------- SIGNOUT
def signout(request):
   logout(request)
   messages.success(request, "logged out syccessfully")
   response = redirect("login")
   response.delete_cookie(key="access_token")
   return response





#-------------------------------------------- HOME
def home(request):
  try:
     access_token=request.COOKIES["access_token"]
     access_token_username = decode_access_token(access_token)
   #   messages.success(request, "You're successfully logged in.")
  except (TypeError, ValueError, OverflowError, KeyError,):
     messages.warning(request, "Session expaired, login again!")
     return redirect('login')
  myuser = User.objects.get(username = access_token_username)
  username = myuser.username
  todo_data = To_do_list.objects.filter(uqid = access_token_username, dele = False).order_by('id').values()
  context = {
     'todo_data': todo_data,
     'username': username,
  }
#   template = loader.get_template("authentication/home.html")
#   return HttpResponse(template.render(context, request))
  return render(request, "authentication/home.html", context)

#-------------------------------------------- ADD TASK
def add(request):
  try:
     access_token=request.COOKIES["access_token"]
     access_token_username = decode_access_token(access_token)
  except (TypeError, ValueError, OverflowError, KeyError,):
     messages.warning(request, "Session expaired, login again!")
     return redirect('login')
  work = request.POST['work']
  myuser = User.objects.get(username = access_token_username)
  work = To_do_list(uqid = myuser.username, to_do=work , isco=False, dele=False)
  work.save()
  return redirect('home')

#-------------------------------------------- DELETE TASK
def delete(request, id):
  try:
     access_token=request.COOKIES["access_token"]
     access_token_username = decode_access_token(access_token)
  except (TypeError, ValueError, OverflowError, KeyError,):
     messages.warning(request, "Session expaired, login again!")
     return redirect('login')
  myuser = User.objects.get(username = access_token_username)
  myuser = To_do_list.objects.get(pk = id)
  myuser.dele = True
  myuser.save()
  return redirect('home')

#-------------------------------------------- TASK COMPLETED
def iscompleted(request, id):
  try:
     access_token=request.COOKIES["access_token"]
     access_token_username = decode_access_token(access_token)
  except (TypeError, ValueError, OverflowError, KeyError,):
     messages.warning(request, "Session expaired, login again!")
     return redirect('login')
  myuser = User.objects.get(username = access_token_username)
  myuser = To_do_list.objects.get(pk = id)
  if myuser.isco == False:
      myuser.isco = True
      myuser.save()
  else:
      myuser.isco = False
      myuser.save()
  return redirect('home')
