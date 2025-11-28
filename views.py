from django.shortcuts import render, redirect, get_object_or_404
from . import models
from django.contrib import messages
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.hashers import check_password
from django.core.exceptions import ValidationError
from datetime import datetime, timedelta
import random, json
from django.http import JsonResponse
from django.core import serializers
from django.utils import timezone
from django.db.models import Q, Case, When, Value
from django.contrib.auth import logout
from django.shortcuts import render, redirect, get_object_or_404
from . import models
from django.contrib import messages
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.hashers import check_password
from django.core.exceptions import ValidationError
from django.core.files.storage import FileSystemStorage
from django.core.paginator import Paginator
from datetime import timedelta
import random, json
from django.http import JsonResponse
from django.core import serializers
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.utils import timezone
from django.db.models import Q, F, Case, When, Value
from django.db.models.functions import Now
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login
from django.contrib.auth import logout
from django.core.mail import send_mail
from django.core.mail import EmailMessage
from django.conf import settings
from django.shortcuts import redirect, render
from django.contrib import messages
from . import models
from django.core.exceptions import ValidationError
import mimetypes
from django.contrib.auth.models import User
from .decorators import role_required
from django.contrib.auth import authenticate, login
from django.core.mail import send_mail
from django.core.mail import EmailMessage
from django.conf import settings
import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO
import qrcode
from django.core.exceptions import ValidationError
import mimetypes
from .decorators import role_required
import traceback
from django.http import JsonResponse
from django.shortcuts import render
from django.db import IntegrityError
import logging
import smtplib

logger = logging.getLogger(__name__)


def index(request):
    return render(request, 'logreg.html')

def logreg(request):
    return render(request, 'logreg.html')

def generate_otp():
    return str(random.randint(100000, 999999))

def forgot_password(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON body.'}, status=400)

        if not email:
            return JsonResponse({'status': 'error', 'message': 'Email is required.'}, status=400)

        # Check if the account exists
        account = models.Account.objects.filter(email=email).first()
        if not account:
            return JsonResponse({'status': 'error', 'message': 'Account not found.'}, status=404)

        # Clean up expired or unused OTPs
        models.OTP.objects.filter(account=account, is_used=False).delete()

        # Generate OTP
        otp_code = generate_otp()

        # Save OTP
        models.OTP.objects.create(account=account, otp_code=otp_code, email=email)

        # Send OTP via email
        try:
            send_mail(
                subject="Password Reset OTP",
                message=f"Your OTP for password reset is {otp_code}. It is valid for 10 minutes.",
                from_email='your_email@example.com',
                recipient_list=[account.email],
            )
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': f'Failed to send email: {str(e)}'}, status=500)

        return JsonResponse({'status': 'success', 'message': 'OTP sent to your email.'})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})

def verify_otp(request):
    if request.method == 'POST':
        try:
            # Parse JSON body
            data = json.loads(request.body)
            email = data.get('email')
            otp_code = data.get('otp')
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON body.'}, status=400)

        # Debug parsed data
        print(f"Email received: {email}, OTP received: {otp_code}")

        if not email or not otp_code:
            return JsonResponse({'status': 'error', 'message': 'Email and OTP are required.'}, status=400)

        # Check if the account exists
        account = models.Account.objects.filter(email=email).first()
        if not account:
            print("Account not found for email:", email)
            return JsonResponse({'status': 'error', 'message': 'Account not found.'}, status=404)

        # Validate OTP for this email and account
        otp_record = models.OTP.objects.filter(account=account, otp_code=otp_code, is_used=False).first()
        if not otp_record:
            print("Invalid OTP for email:", email)
            return JsonResponse({'status': 'error', 'message': 'Invalid OTP.'})

        # Check if OTP has expired
        if otp_record.is_expired():
            print("OTP has expired for email:", email)
            return JsonResponse({'status': 'error', 'message': 'OTP has expired.'})

        # Mark the OTP as used
        otp_record.is_used = True
        otp_record.save()
        otp_record.delete()

        print("OTP verified successfully for email:", email)
        return JsonResponse({'status': 'success', 'message': 'OTP verified successfully.'})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})

def reset_password(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')
            new_password = data.get('new_password')
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON body.'}, status=400)

        # Validate inputs
        if not email or not new_password:
            return JsonResponse({'status': 'error', 'message': 'Email and new password are required.'}, status=400)

        # Retrieve the account
        account = models.Account.objects.filter(email=email).first()
        if not account:
            return JsonResponse({'status': 'error', 'message': 'Account not found.'}, status=404)

        # Check if the new password matches the current password
        if check_password(new_password, account.password):
            return JsonResponse({'status': 'error', 'message': 'New password cannot be the same as the current password.'}, status=400)

        # Update password
        account.password = make_password(new_password)
        account.save()

        return JsonResponse({'status': 'success', 'message': 'Password reset successful.'})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=405)

def create_account(request):
    if request.method == 'POST':
        try:
            # Parse JSON request
            data = json.loads(request.body)
            firstname = data.get('firstname', '').strip()
            middlename = data.get('middlename', '').strip()
            lastname = data.get('lastname', '').strip()
            birthday = data.get('birthday', '').strip()
            address = data.get('address', '').strip()
            email = data.get('email', '').strip()
            username = data.get('username', '').strip()
            password = data.get('password', '').strip()
            confirmpassword = data.get('confirmpassword', '').strip()

            # Validate required fields
            if not firstname or not lastname or not birthday or not username or not password:
                return JsonResponse({'status': 'error', 'message': 'Missing required fields.'}, status=400)

            # Check password confirmation
            if password != confirmpassword:
                return JsonResponse({'status': 'error', 'message': 'Passwords do not match.'}, status=400)

            # Check if the username is reserved
            if username == "JSXHOTEL_ADMIN":
                return JsonResponse({'status': 'error', 'message': 'The username "JSXHOTEL_ADMIN" is reserved.'}, status=400)

            # Check if the username or email already exists
            if models.Account.objects.filter(username=username).exists():
                return JsonResponse({'status': 'error', 'message': 'Username already taken.'}, status=400)

            if models.Account.objects.filter(email=email).exists():
                return JsonResponse({'status': 'error', 'message': 'Email already used.'}, status=400)

            # Check if the email exists in the Blocklist
            if models.Blocklist.objects.filter(email=email).exists():
                return JsonResponse({'status': 'error', 'message': 'This email address is blocked.'}, status=403)

            # Check age
            today = datetime.date.today()
            birth_date = datetime.datetime.strptime(birthday, '%Y-%m-%d').date()
            age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
            if age < 18:
                return JsonResponse({'status': 'error', 'message': 'You must be at least 18 years old to register.'}, status=400)

            # Hash the password
            hashed_password = make_password(password)

            # Create the user account
            account = models.Account.objects.create(
                firstname=firstname,
                middlename=middlename,
                lastname=lastname,
                birthday=birthday,
                address=address,
                email=email,
                username=username,
                password=hashed_password,  # Store the hashed password
            )
            account.save()

            # Send welcome email
            send_mail(
                subject="Welcome to JSXHotel!",
                message=(
                    f"Dear {firstname} {lastname},\n\n"
                    "Welcome to JSXHotel! We're thrilled to have you on board.\n\n"
                    "Feel free to explore our services and reach out to us for any assistance.\n\n"
                    "Best regards,\nThe JSXHotel Team"
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,  # Replace with your sender email
                recipient_list=[email],
                fail_silently=False,  # Set to True in production to avoid interruptions
            )

            return JsonResponse({'status': 'success', 'message': 'Account created successfully!'})

        except ValueError as e:
            return JsonResponse({'status': 'error', 'message': f'Invalid data: {str(e)}'}, status=400)
        except IntegrityError as e:
            return JsonResponse({'status': 'error', 'message': f'Integrity error: {str(e)}'}, status=400)
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': f'Unexpected error: {str(e)}'}, status=500)

    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=405)

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user_account = models.Account.objects.filter(username=username).first()
        user_hr = models.HrAccount.objects.filter(username=username).first()
        user_admin = models.Admin.objects.filter(username=username).first()
        
        if user_account and check_password(password, user_account.password):
            request.session['user_role'] = 'guest'
            request.session['user_id'] = user_account.id
            return redirect('dashboard')
        
        elif user_hr:
            if user_hr.password_status == 'NO':
                request.session['user_role'] = 'hr'
                request.session['user_id'] = user_hr.id
                return redirect('hr_pass')  # Redirect to the HR password update page
            else:
                request.session['user_role'] = 'hr'
                request.session['user_id'] = user_hr.id
                return redirect('receptionist')
            
        elif user_admin and check_password(password, user_admin.password):
            request.session['user_role'] = 'admin'
            request.session['user_id'] = user_admin.id
            return redirect('home_ad')
        else:
            messages.error(request, 'Invalid username or password')
    return render(request, 'logreg.html')

@role_required('hr')
def hr_pass_view(request):
    if request.method == 'GET':
        return render(request, 'hr_pass.html')  # Render the `hr_pass.html` template

    elif request.method == 'POST':
        # Get user ID from session
        user_id = request.session.get('user_id')
        if not user_id:
            return JsonResponse({'status': 'error', 'message': 'User not authenticated.'}, status=403)

        # Fetch the HR account
        user_hr = models.HrAccount.objects.filter(id=user_id).first()
        if not user_hr:
            return JsonResponse({'status': 'error', 'message': 'User not found.'}, status=404)

        # Get passwords from the POST data
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        # Validate the inputs
        if not current_password or not new_password or not confirm_password:
            return JsonResponse({'status': 'error', 'message': 'All fields are required.'}, status=400)
        if not check_password(current_password, user_hr.password):
            return JsonResponse({'status': 'error', 'message': 'Current password is incorrect.'}, status=400)
        if new_password != confirm_password:
            return JsonResponse({'status': 'error', 'message': 'Passwords do not match.'}, status=400)
        if len(new_password) < 8:
            return JsonResponse({'status': 'error', 'message': 'Password must be at least 8 characters long.'}, status=400)

        # Update the password
        user_hr.password = make_password(new_password)
        user_hr.password_status = 'YES'
        user_hr.save()

        # Log out the user and redirect to login page
        return JsonResponse({'status': 'success', 'message': 'Password updated successfully. Please log in again.'})

def logout_view(request):
    logout(request) 
    return redirect('logreg')  

def generate_unique_reference_id():
    while True:
        reference_id = ''.join(random.choices('0123456789', k=8))
        if not models.reservation.objects.filter(reference_id=reference_id).exists():
            return reference_id

def is_room_available(room_type, check_in, check_out):
    overlapping_reservations = models.reservation.objects.filter(
        room_type=room_type,
        check_in__lt=check_out,
        check_out__gt=check_in,
        status='PENDING'
    ).count()
    return overlapping_reservations < 10

def get_logged_in_user(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return None
    return models.Account.objects.get(id=user_id)

##### guest

@role_required('guest')
def create_reservation(request):
    account = get_logged_in_user(request)
    if not account:
        return JsonResponse({'success': False, 'message': 'User not logged in. Please log in to make a reservation.'})

    if request.method == 'POST':
        room_type = request.POST.get('room')
        check_in = request.POST.get('check-in-datetime')
        check_out = request.POST.get('check-out-datetime')
        receipt = request.FILES.get('receipt')

        try:
            # Parse and validate check-in and check-out dates
            check_in_date = datetime.datetime.strptime(check_in, "%Y-%m-%d").date()
            check_out_date = datetime.datetime.strptime(check_out, "%Y-%m-%d").date()

            if not room_type:
                return JsonResponse({'success': False, 'message': 'Please select a room type.'})

            # Ensure reservation duration does not exceed 6 months
            if (check_out_date - check_in_date).days > 180:
                return JsonResponse({'success': False, 'message': 'Reservation duration cannot exceed 6 months.'})

            # Check room availability
            if not is_room_available(room_type, check_in, check_out):
                return JsonResponse({'success': False, 'message': f"Rooms of type '{room_type}' are unavailable for the selected dates."})

            # Create the reservation object but don't save yet
            new_reservation = models.reservation(
                email=account.email,
                firstname=account.firstname,
                middlename=account.middlename,
                lastname=account.lastname,
                reference_id=generate_unique_reference_id(),
                check_in=check_in_date,
                check_out=check_out_date,
                room_type=room_type,
                typeofbooking='ONLINE',
                status='WAITING FOR APPROVAL',
                receipt=receipt
            )

            # Generate the reservation details PDF
            buffer = BytesIO()
            pdf = canvas.Canvas(buffer, pagesize=letter)
            pdf.drawString(100, 750, "Reservation Details - JSX Hotel")
            pdf.drawString(100, 720, f"Reference ID: {new_reservation.reference_id}")
            pdf.drawString(100, 700, f"Name: {account.firstname} {account.middlename} {account.lastname}")
            pdf.drawString(100, 680, f"Room Type: {room_type}")
            pdf.drawString(100, 660, f"Check-in: {check_in}")
            pdf.drawString(100, 640, f"Check-out: {check_out}")
            pdf.drawString(100, 620, "Status: WAITING FOR APPROVAL")
            pdf.drawString(100, 600, "This reservation is pending admin approval.")
            pdf.save()
            buffer.seek(0)

            # Send email to the user
            email = EmailMessage(
                subject="Reservation Created - Pending Approval",
                body=(
                    f"Dear {account.firstname},\n\n"
                    f"Thank you for your reservation. Below are the details:\n"
                    f"Reference ID: {new_reservation.reference_id}\n"
                    f"Room Type: {room_type}\n"
                    f"Check-in: {check_in}\n"
                    f"Check-out: {check_out}\n\n"
                    "This reservation is pending admin approval.\n\n"
                    "Best regards,\nJSX Hotel"
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[account.email]
            )
            email.attach('reservation_details.pdf', buffer.getvalue(), 'application/pdf')

            if receipt:
                mime_type, _ = mimetypes.guess_type(receipt.name)
                email.attach(receipt.name, receipt.read(), mime_type or 'application/octet-stream')

            # Force email sending to raise an exception if it fails
            email.send(fail_silently=False)

            # Save the reservation only after email is successfully sent
            new_reservation.save()
            return JsonResponse({'success': True, 'message': 'Reservation created successfully.'})

        except smtplib.SMTPException as email_error:
            return JsonResponse({'success': False, 'message': 'Failed to send confirmation email. Please ensure your email is valid.'})

        except ValidationError as e:
            return JsonResponse({'success': False, 'message': f"Validation error: {e}"})

        except Exception as e:
            return JsonResponse({'success': False, 'message': f"An unexpected error occurred: {e}"})

    return render(request, 'booking.html')

@role_required('guest')
def account(request):
    account = get_logged_in_user(request)
    if not account:
        return redirect('logreg.html')  # Redirect to login if user is not authenticated

    context = {
        'first_name': account.firstname,
        'middle_name': account.middlename,
        'last_name': account.lastname,
        'address': account.address,
        'email': account.email
    }
    return render(request, 'account.html', context)

@role_required('guest')
def booking_view(request):
    promotions = models.RoomPromotion.objects.filter(is_active=True)  # Get only active promotions
    context = {
        'promotions': promotions,
    }
    return render(request, 'booking.html', context)

@role_required('guest')
def reservations(request):
    account = get_logged_in_user(request)
    if not account:
        return redirect('login')

    try:
        user_email = account.email

        # Fetch and combine reservations, sorted by check-in date
        user_reservations = models.reservation.objects.filter(email=user_email).order_by('check_in')
        user_archived_reservations = models.ArchiveReservation.objects.filter(email=user_email).order_by('check_in')

        all_reservations = sorted(
            list(user_reservations) + list(user_archived_reservations),
            key=lambda res: res.check_in
        )

        return render(request, 'reservations.html', {'reservations': all_reservations})
    except Exception as e:
        print(f"Error fetching reservations: {e}")
        return render(request, 'error.html', {'message': 'Could not load reservations.'})

@role_required('guest')
def cancel_reservation(request, reservation_id):
    account = get_logged_in_user(request)
    if not account:
        return redirect('login')

    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            reason = data.get('reason', '')

            reservation_instance = get_object_or_404(models.reservation, reference_id=reservation_id)
            if reservation_instance.cancelstatus == "CANCELLATION PENDING":
                return JsonResponse({'success': False, 'message': 'Cancellation already requested.'})

            reservation_instance.cancelreason = reason
            reservation_instance.cancel_date = timezone.now()
            reservation_instance.cancelstatus = 'CANCELLATION PENDING'
            reservation_instance.save()

            return JsonResponse({'success': True})
        except Exception as e:
            print(f"Error cancelling reservation: {e}")
            return JsonResponse({'success': False, 'message': 'An error occurred while processing your request.'})

    return JsonResponse({'success': False, 'message': 'Invalid request method'})

@role_required('guest')
def dashboard(request):
    account = get_logged_in_user(request)
    if not account:
        return redirect('login')

    images = models.HomepageImage.objects.all()[:4]  # Limit to 4 images
    return render(request, 'dashboard.html', {'images': images})

##### hr

@role_required('hr')
def submit_walk_in_reservation(request):
    if request.method == 'POST':
        first_name = request.POST.get('firstname')
        middle_name = request.POST.get('middlename', '')
        last_name = request.POST.get('lastname')
        email = request.POST.get('email')
        room_type = request.POST.get('room')
        check_in = request.POST.get('check_in')
        check_out = request.POST.get('check_out')

        # Check if the email is blocklisted
        if models.Blocklist.objects.filter(email=email).exists():
            return JsonResponse({'success': False, 'message': "This email is blocklisted and cannot be used for a reservation."})

        try:
            # Parse and validate check-in and check-out dates
            check_in_date = datetime.datetime.strptime(check_in, "%Y-%m-%d").date()
            check_out_date = datetime.datetime.strptime(check_out, "%Y-%m-%d").date()

            if not room_type:
                return JsonResponse({'success': False, 'message': "Please select a room type."})

            if (check_out_date - check_in_date).days > 180:
                return JsonResponse({'success': False, 'message': "Reservation duration cannot exceed 6 months."})

            if not is_room_available(room_type, check_in_date, check_out_date):
                return JsonResponse({'success': False, 'message': f"All rooms of type {room_type} are booked for the selected dates."})

            # Generate the QR code
            qr_data = (
                f"Reservation Details:\n"
                f"Reference ID: {generate_unique_reference_id()}\n"
                f"Name: {first_name} {middle_name} {last_name}\n"
                f"Room Type: {room_type}\n"
                f"Check-in: {check_in}\n"
                f"Check-out: {check_out}"
            )
            qr = qrcode.make(qr_data)
            qr_buffer = BytesIO()
            qr.save(qr_buffer, format="PNG")
            qr_buffer.seek(0)

            # Prepare email
            email_message = EmailMessage(
                subject="Reservation Confirmation - JSX Hotel",
                body=(
                    f"Dear {first_name},\n\n"
                    f"Thank you for your reservation at JSX Hotel. Below are your reservation details:\n"
                    f"Room Type: {room_type}\n"
                    f"Check-in: {check_in}\n"
                    f"Check-out: {check_out}\n\n"
                    "Scan the attached QR code for quick access to your reservation details.\n\n"
                    "Best regards,\nJSX Hotel"
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[email],
            )

            # Attach the QR code
            email_message.attach('reservation_qr_code.png', qr_buffer.getvalue(), 'image/png')

            try:
                # Attempt to send email
                email_message.send(fail_silently=False)
            except smtplib.SMTPException:
                return JsonResponse({'success': False, 'message': "The email address provided is invalid or unreachable. Please provide a valid email."})

            # Create the reservation only if the email was sent successfully
            new_reservation = models.reservation.objects.create(
                email=email,
                firstname=first_name,
                middlename=middle_name,
                lastname=last_name,
                reference_id=generate_unique_reference_id(),
                check_in=check_in_date,
                check_out=check_out_date,
                room_type=room_type,
                typeofbooking='WALK IN',
                status='PENDING',
            )

            return JsonResponse({'success': True, 'message': "Reservation submitted successfully!"})

        except Exception as e:
            return JsonResponse({'success': False, 'message': f"An unexpected error occurred: {str(e)}"})

    return JsonResponse({'success': False, 'message': "Invalid request method."})

    return JsonResponse({'success': False, 'message': "Invalid request method."})

@role_required('hr')
def receptionist_view(request):
    # Calculate the date 6 months ago
    six_months_ago = timezone.now() - timedelta(days=6*30)
    today = timezone.now().date()  # Get the current date

    # Get the search query from the GET parameters
    query = request.GET.get("q", "")

    # Filter reservations within the last 6 months, exclude "WAITING FOR APPROVAL" status,
    # and order by today's check-ins first
    reservations = models.reservation.objects.filter(
        timestamp__gte=six_months_ago
    ).exclude(
        status="WAITING FOR APPROVAL"  # Exclude reservations with this status
    ).annotate(
        # Annotate with a priority field that marks today's check-ins
        priority=Case(
            When(check_in=today, then=Value(0)),  # Today's check-ins have the highest priority (0)
            default=Value(1),  # All other check-ins have lower priority (1)
        )
    ).order_by('priority', 'check_in')  # First sort by priority, then by check-in date

    # Apply additional filtering if a search query is provided
    if query:
        reservations = reservations.filter(
            Q(reference_id__icontains=query) | 
            Q(firstname__icontains=query) | 
            Q(lastname__icontains=query)
        )

    return render(request, 'receptionist.html', {'reservations': reservations, 'query': query})

@role_required('hr')
def update_status(request):
    if request.method == "POST":
        reference_id = request.POST.get("reference_id")
        new_status = request.POST.get("status")

        # Find the reservation and update the status
        try:
            reservation_obj = models.reservation.objects.get(reference_id=reference_id)
            old_status = reservation_obj.status  # Save the old status for reference
            reservation_obj.status = new_status
            reservation_obj.save()

            # Send an email notification if the new status is not "PENDING"
            if new_status != "PENDING":
                send_status_update_email(reservation_obj, old_status, new_status)

            return JsonResponse({"success": True, "status": new_status})
        except models.reservation.DoesNotExist:
            return JsonResponse({"success": False, "error": "Reservation not found."})
    
    return JsonResponse({"success": False, "error": "Invalid request method."})

def send_status_update_email(reservation, old_status, new_status):
    # Build the email subject
    subject = f"Reservation Status Update - JSX Hotel"

    # Build the email body
    if new_status == "OVERSTAYING":
        body = (
            f"Dear {reservation.firstname} {reservation.lastname},\n\n"
            f"We would like to inform you that the status of your reservation with reference ID "
            f"{reservation.reference_id} has been updated to OVERSTAYING.\n\n"
            f"Your reservation period has ended, and you are requested to vacate the room within the next hour.\n"
            f"Failure to do so may result in being flagged as a repeat offender and banned from future reservations at JSX Hotel.\n\n"
            f"Thank you for your immediate attention to this matter.\n\n"
            f"Best regards,\n"
            f"JSX Hotel Management"
        )
    else:
        body = (
            f"Dear {reservation.firstname} {reservation.lastname},\n\n"
            f"We would like to inform you that the status of your reservation with reference ID "
            f"{reservation.reference_id} has been updated.\n\n"
            f"Previous Status: {old_status}\n"
            f"New Status: {new_status}\n\n"
            f"Thank you for choosing JSX Hotel.\n\n"
            f"Best regards,\n"
            f"JSX Hotel Management"
        )

    # Send the email
    email = EmailMessage(
        subject,
        body,
        settings.DEFAULT_FROM_EMAIL,
        [reservation.email]
    )
    email.send(fail_silently=False)

@role_required('hr')
def walkin_reservation_view(request):
    promotions = models.RoomPromotion.objects.filter(is_active=True)  # Get only active promotions
    context = {
        'promotions': promotions,
    }
    return render(request, 'walkins.html', context)

def update_password(request):
    if request.method == 'POST':
        user_id = request.session.get('user_id')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if new_password != confirm_password:
            return JsonResponse({'status': 'error', 'message': 'Passwords do not match.'})

        user_hr = models.HrAccount.objects.filter(id=user_id).first()
        if user_hr:
            user_hr.password = make_password(new_password)
            user_hr.password_status = 'YES'  # Update status
            user_hr.save()
            return JsonResponse({'status': 'success', 'message': 'Password updated successfully.'})

        return JsonResponse({'status': 'error', 'message': 'User not found.'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request.'})

##### admin

@role_required('admin')
def admin_reservations(request):
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        # Fetch only reservations with 'WAITING FOR APPROVAL'
        reservations = models.reservation.objects.filter(status='WAITING FOR APPROVAL')
        reservations_data = serializers.serialize('json', reservations)
        return JsonResponse(reservations_data, safe=False)

    # Regular response for non-AJAX requests
    pending_reservations = models.reservation.objects.filter(status='WAITING FOR APPROVAL')
    return render(request, 'rsv_req_ad.html', {'reservations': pending_reservations})

@role_required('admin')
def admin_homepage_edit(request):
    if request.method == 'POST':
        updates = []  # Collect updates for response
        for i in range(1, 5): 
            file_field = f'file{i}'
            title_field = f'title{i}'
            description_field = f'description{i}'

            homepage_image, created = models.HomepageImage.objects.get_or_create(id=i)

            new_image = request.FILES.get(file_field, None)
            new_title = request.POST.get(title_field, homepage_image.title)
            new_description = request.POST.get(description_field, homepage_image.description)

            if (
                (new_image and new_image != homepage_image.image) or
                new_title != homepage_image.title or
                new_description != homepage_image.description
            ):
                # Archive the current data before updating if there's a change
                if homepage_image.image:
                    models.ArchiveHomepageImage.objects.create(
                        image=homepage_image.image,
                        title=homepage_image.title,
                        description=homepage_image.description,
                        archived_at=timezone.now()
                    )

                # Update the homepage image with the new data
                if new_image:
                    homepage_image.image = new_image
                homepage_image.title = new_title
                homepage_image.description = new_description
                homepage_image.save()

                updates.append(f"Image {i} updated successfully")

        # Check if this is an AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            if updates:
                return JsonResponse({'status': 'success', 'message': updates})
            else:
                return JsonResponse({'status': 'info', 'message': 'No changes made.'})

        # For standard form submissions, redirect to the homepage
        messages.success(request, "Images, titles, and descriptions updated successfully!")
        return redirect('home_ad')

    images = models.HomepageImage.objects.all().order_by('id')
    return render(request, 'home_ad.html', {'images': images})

@role_required('admin')
def admin_homepage_view(request):
    # Fetch all images from the database to display on the page
    images = models.HomepageImage.objects.all().order_by('id')
    return render(request, 'home_ad.html', {'images': images})

@role_required('admin')
def update_request_status(request, reservation_id):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            action = data.get('action')
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON'}, status=400)

        if not action:
            return JsonResponse({'status': 'error', 'message': 'Action not specified'}, status=400)

        reservation = get_object_or_404(models.reservation, reference_id=reservation_id)

        if action == 'approve':
            reservation.status = 'PENDING'
            reservation.save()

            # Generate QR Code
            qr_data = f"Reservation Details:\nReference ID: {reservation.reference_id}\n" \
                      f"Name: {reservation.firstname} {reservation.lastname}\n" \
                      f"Check-in: {reservation.check_in}\nCheck-out: {reservation.check_out}\n" \
                      f"Room Type: {reservation.room_type}"
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(qr_data)
            qr.make(fit=True)

            # Save QR code to an in-memory buffer
            img = qr.make_image(fill='black', back_color='white')
            buffer = BytesIO()
            img.save(buffer, format='PNG')
            buffer.seek(0)

            # Send email with the QR code attached
            email = EmailMessage(
                subject="Reservation Approved",
                body=f"Dear {reservation.firstname},\n\nYour reservation with reference ID {reservation.reference_id} "
                     f"has been approved and is now set to PENDING.\n\nPlease find your QR code attached for reference.\n\n"
                     f"Thank you for choosing our service.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[reservation.email],
            )
            email.attach(f"{reservation.reference_id}_qr.png", buffer.read(), 'image/png')
            email.send(fail_silently=False)
            buffer.close()

            return JsonResponse({'status': 'success', 'new_status': reservation.status})

        elif action == 'decline':
            reservation.status = 'RESERVATION DECLINED'
            print(f"Reservation with reference ID {reservation.reference_id} marked as declined.")

            archived_reservation = models.ArchiveReservation.objects.create(
                email=reservation.email,
                firstname=reservation.firstname,
                middlename=reservation.middlename,
                lastname=reservation.lastname,
                reference_id=reservation.reference_id,
                check_in=reservation.check_in,
                check_out=reservation.check_out,
                room_type=reservation.room_type,
                typeofbooking=reservation.typeofbooking,
                status=reservation.status,
                receipt=reservation.receipt
            )
            print(f"Archived reservation with reference ID {reservation.reference_id}.")

            # Send email for decline
            email = EmailMessage(
                subject="Reservation Declined",
                body=f"Dear {reservation.firstname},\n\nWe regret to inform you that your reservation with reference ID {reservation.reference_id} has been declined. If you have any questions, please contact us.\n\nThank you.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[reservation.email],
            )
            if reservation.receipt:
                mime_type, _ = mimetypes.guess_type(reservation.receipt.name)
                email.attach(reservation.receipt.name, reservation.receipt.read(), mime_type or 'application/octet-stream')
            email.send(fail_silently=False)

            reservation.delete()
            print(f"Deleted original reservation with reference ID {reservation.reference_id} after archiving.")

            return JsonResponse({'status': 'success', 'new_status': 'RESERVATION DECLINED'})

        else:
            return JsonResponse({'status': 'error', 'message': 'Invalid action'}, status=400)

    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=400)

@role_required('admin')
def manage_hr_accounts(request):
    # Handle form submission (POST request)
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirmpassword')

        # Validate passwords
        if password != confirm_password:
            return JsonResponse({'success': False, 'message': 'Passwords do not match.'})

        # Check if the username already exists in HrAccount
        if models.HrAccount.objects.filter(username=username).exists():
            return JsonResponse({'success': False, 'message': 'Username is already taken.'})

        # Check if the username already exists in ArchiveHrAccount
        if models.ArchiveHrAccount.objects.filter(username=username).exists():
            return JsonResponse({'success': False, 'message': 'Username was already used.'})

        # Create and save the new HR account
        try:
            hashed_password = make_password(password)
            models.HrAccount.objects.create(
                username=username,
                password=hashed_password,
                password_status='NO',  # Initial status for password
                hraccount_status='ACTIVE'  # Initial status for account
            )
            return JsonResponse({'success': True, 'message': 'Account created successfully.'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': f'An unexpected error occurred: {str(e)}'})

    # Handle AJAX request for fetching accounts
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        accounts = models.HrAccount.objects.filter(hraccount_status='ACTIVE')
        accounts_data = serializers.serialize('json', accounts)
        return JsonResponse({'success': True, 'accounts': accounts_data, 'message': 'Accounts fetched successfully.'})

    # Default: Render the template for GET requests
    accounts = models.HrAccount.objects.filter(hraccount_status='ACTIVE')
    return render(request, 'acc_ad.html', {'accounts': accounts})

@role_required('admin')
def check_username(request):
    username = request.GET.get('username')
    exists = models.HrAccount.objects.filter(username=username).exists()
    exists = models.ArchiveHrAccount.objects.filter(username=username).exists()
    return JsonResponse({'exists': exists})

@role_required('admin')
def update_hr_status(request, username):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'message': 'Invalid JSON payload'})

        new_status = data.get('status')
        if new_status not in ['ACTIVE', 'DEACTIVATED']:
            return JsonResponse({'success': False, 'message': 'Invalid status value'})

        try:
            account = models.HrAccount.objects.get(username=username)

            if new_status == 'DEACTIVATED':
                archived_account, created = models.ArchiveHrAccount.objects.get_or_create(
                    username=account.username,
                    defaults={
                        'password': account.password,
                        'password_status': account.password_status,
                        'hraccount_status': new_status
                    }
                )
                if not created:
                    archived_account.hraccount_status = new_status
                    archived_account.save()

                account.delete()
            else:
                account.hraccount_status = new_status
                account.save()

            return JsonResponse({'success': True, 'message': f'Account {username} status updated to {new_status}.'})
        except models.HrAccount.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'Account not found'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': f'Unexpected error: {str(e)}'})

    return JsonResponse({'success': False, 'message': 'Invalid request method.'}, status=405)

@role_required('admin')
def room_promotions_view(request):
    if request.method == 'POST':
        try:
            room_name = request.POST.get('room_name')
            price = request.POST.get('price')

            # Validate price
            if not price or not price.replace('.', '', 1).isdigit() or float(price) <= 0:
                return JsonResponse({'success': False, 'message': 'Invalid price. Please enter a positive number.'})

            description = request.POST.get('description')
            image = request.FILES.get('image')

            # Save promotion
            models.RoomPromotion.objects.create(
                room_name=room_name,
                price=price,
                description=description,
                image=image,
            )

            return JsonResponse({'success': True, 'message': 'Room promotion added successfully!'})

        except ValueError:
            return JsonResponse({'success': False, 'message': 'Invalid price format. Please use numeric values only.'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': f'An unexpected error occurred: {str(e)}'})

    return JsonResponse({'success': False, 'message': 'Invalid request method.'})

@role_required('admin')
def booking_ad_view(request):
    promotions = models.RoomPromotion.objects.filter(is_active=True)
    return render(request, 'booking_ad.html', {'promotions': promotions})

@role_required('admin')
def deactivate_promotion(request, room_id):
    if request.method == 'POST':
        try:
            # Retrieve the RoomPromotion object based on room_id
            promotion = models.RoomPromotion.objects.filter(room_name=room_id).first()
            if not promotion:
                return JsonResponse({'success': False, 'message': 'The specified room does not have an active promotion.'}, status=404)

            # Prevent deactivation of standard rooms
            standard_rooms = ['room1', 'room2', 'room3', 'room4', 'room5']
            if promotion.room_name in standard_rooms:
                return JsonResponse({'success': False, 'message': f'The room {promotion.room_name} cannot be deactivated.'}, status=403)

            # Validate promotion fields
            if not all([promotion.room_name, promotion.description, promotion.price]):
                return JsonResponse({'success': False, 'message': 'Promotion data is incomplete. Cannot archive.'}, status=400)

            # Archive the promotion
            try:
                models.ArchiveRoomPromotion.objects.create(
                    room_name=promotion.room_name,
                    price=promotion.price,
                    description=promotion.description,
                    image=promotion.image,
                    is_active=False
                )
            except Exception as e:
                return JsonResponse({'success': False, 'message': f'Failed to archive promotion: {str(e)}'}, status=500)

            # Delete the original promotion
            try:
                promotion.delete()
            except Exception as e:
                return JsonResponse({'success': False, 'message': f'Failed to delete the original promotion: {str(e)}'}, status=500)

            return JsonResponse({'success': True, 'message': 'Room promotion successfully deactivated and archived.'}, status=200)

        except Exception as e:
            # Log unexpected errors for debugging
            return JsonResponse({'success': False, 'message': f'An unexpected error occurred: {str(e)}'}, status=500)

    return JsonResponse({'success': False, 'message': 'Invalid request method. Only POST is allowed.'}, status=405)


@role_required('admin')
def cncl_req_ad(request):
    cancellations = models.reservation.objects.filter(cancelstatus='CANCELLATION PENDING')
    return render(request, 'cncl_req_ad.html', {'cancellations': cancellations})

@role_required('admin')
def update_cancellation_status(request, reservation_id):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            action = data.get('action')
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON'}, status=400)
        if not action:
            return JsonResponse({'status': 'error', 'message': 'Action not specified'}, status=400)
        
        reservation = get_object_or_404(models.reservation, reference_id=reservation_id)

        if action == 'approve':
            reservation.cancelstatus = 'CANCELLATION APPROVED'
            reservation.status = 'CANCELLED'
            
            # Archive the reservation
            archived_reservation = models.ArchiveReservation.objects.create(
                reference_id=reservation.reference_id,
                email=reservation.email,
                firstname=reservation.firstname,
                middlename=reservation.middlename,
                lastname=reservation.lastname,
                check_in=reservation.check_in,
                check_out=reservation.check_out,
                room_type=reservation.room_type,
                typeofbooking=reservation.typeofbooking,
                status=reservation.status,
                receipt=reservation.receipt,
                cancel_date=reservation.cancel_date,
                cancelreason=reservation.cancelreason,
                cancelstatus=reservation.cancelstatus,
            )
            print(f"Archived reservation with reference ID {reservation.reference_id}.")
            
            # Delete the original reservation
            reservation.delete()
            print(f"Deleted reservation with reference ID {reservation.reference_id} after archiving.")
            
            # Send cancellation approval email
            email = EmailMessage(
                subject="Cancellation Approved",
                body=f"Dear {archived_reservation.firstname},\n\nYour cancellation request for reservation ID {archived_reservation.reference_id} has been approved. The reservation has been cancelled.\n\nThank you.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[archived_reservation.email],
            )
            # Attach receipt if available
            if archived_reservation.receipt:
                mime_type, _ = mimetypes.guess_type(archived_reservation.receipt.name)
                email.attach(archived_reservation.receipt.name, archived_reservation.receipt.read(), mime_type or 'application/octet-stream')
            email.send(fail_silently=False)
            
            return JsonResponse({'status': 'success', 'cancelstatus': 'CANCELLATION APPROVED'})

        elif action == 'decline':
            reservation.cancelstatus = 'CANCELLATION DECLINED'
            reservation.status = 'PENDING'
            reservation.save()
            print(f"Reservation with reference ID {reservation.reference_id} approved and set to PENDING.")
            
            # Send cancellation decline email
            email = EmailMessage(
                subject="Cancellation Declined",
                body=f"Dear {reservation.firstname},\n\nYour cancellation request for reservation ID {reservation.reference_id} has been declined. The reservation remains active with status PENDING.\n\nThank you.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[reservation.email],
            )
            email.send(fail_silently=False)
            
            return JsonResponse({'status': 'success', 'cancelstatus': 'CANCELLATION DECLINED'})
        
        else:
            return JsonResponse({'status': 'error', 'message': 'Invalid action'}, status=400)

    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=400)

@role_required('admin')
def archive_view(request):
    context = {
        'archive_accounts': models.ArchiveAccount.objects.all(),
        'archive_homepage_images': models.ArchiveHomepageImage.objects.all(),
        'archive_hraccount': models.ArchiveHrAccount.objects.all(),
        'archive_reservation': models.ArchiveReservation.objects.all(),
        'archive_room_promotions': models.ArchiveRoomPromotion.objects.all(),
        'blocklist': models.Blocklist.objects.all(),
    }
    return render(request, 'archived_bookings.html', context)

@role_required('admin')
def settlements_list(request):
    overstaying_reservations = models.reservation.objects.filter(status="OVERSTAYING")
    return render(request, 'settlements_ad.html', {'reservations': overstaying_reservations})

@role_required('admin')
def update_settlement(request, reference_id):
    if request.method == 'POST':
        settlement_status = request.POST.get('settlements')
        reservation = get_object_or_404(models.reservation, reference_id=reference_id)
        
        try:
            if settlement_status == "Blocklisted":
                # Blocklisting Process
                if reservation.email:
                    try:
                        handle_account_blocklisting(reservation.email)
                    except models.Account.DoesNotExist:
                        handle_walkin_blocklisting(reservation)
                else:
                    handle_walkin_blocklisting(reservation)

                archive_reservation(reservation, settlement_status)
                reservation.delete()

                # Send email
                send_settlement_email(reservation, settlement_status)

                return JsonResponse({
                    "success": True,
                    "message": f"Reservation {reference_id} has been blocklisted successfully."
                })

            else:
                # Settlement Status Update
                reservation.settlements = settlement_status
                reservation.status = 'CHECKED-OUT'
                reservation.save()

                # Send email
                send_settlement_email(reservation, settlement_status)

                return JsonResponse({
                    "success": True,
                    "message": f"Settlement status for reservation {reference_id} has been updated successfully."
                })

        except Exception as e:
            return JsonResponse({
                "success": False,
                "message": "An unexpected error occurred. Please try again."
            })

@role_required('admin')
def acc_ad(request):
    return render(request, 'acc_ad.html')

def handle_account_blocklisting(email):
    print(f"Handling blocklisting for account with email: {email}")
    account = models.Account.objects.get(email=email)
    
    models.ArchiveAccount.objects.create(
        firstname=account.firstname,
        middlename=account.middlename,
        lastname=account.lastname,
        address=account.address,
        birthday=account.birthday,
        email=account.email,
        username=account.username,
        password=account.password
    )
    print("Account archived successfully.")

    # Add to blocklist
    models.Blocklist.objects.create(
        firstname=account.firstname,
        middlename=account.middlename,
        lastname=account.lastname,
        email=account.email
    )
    print("Blocklist entry created successfully for account.")

    # Delete the account
    account.delete()
    print("Original account deleted.")

def handle_walkin_blocklisting(reservation):
    print(f"Handling blocklisting for WALK-IN reservation with reference_id: {reservation.reference_id}")
    models.Blocklist.objects.create(
        firstname=reservation.firstname,
        middlename=reservation.middlename,
        lastname=reservation.lastname,
        email=reservation.email  # Handle missing email
    )
    print("Blocklist entry created successfully for WALK-IN.")

def archive_reservation(reservation, settlement_status):
    print(f"Archiving reservation with reference_id: {reservation.reference_id}")
    models.ArchiveReservation.objects.create(
        email=reservation.email,
        firstname=reservation.firstname,
        middlename=reservation.middlename,
        lastname=reservation.lastname,
        reference_id=reservation.reference_id,
        check_in=reservation.check_in,
        check_out=reservation.check_out,
        room_type=reservation.room_type,
        typeofbooking=reservation.typeofbooking,
        status=reservation.status,
        receipt=reservation.receipt if hasattr(reservation, 'receipt') and reservation.receipt else None,
        timestamp=reservation.timestamp,
        cancel_date=reservation.cancel_date,
        cancelreason=reservation.cancelreason,
        cancelstatus=reservation.cancelstatus,
        settlements=settlement_status
    )
    print("Reservation archived successfully.")
    
def send_settlement_email(reservation, settlement_status):
    """
    Sends an email to notify the guest about the updated settlement status or blocklisting.
    """
    subject = f"Reservation Update - Reference ID {reservation.reference_id}"
    if settlement_status == "Blocklisted":
        body = (
            f"Dear {reservation.firstname} {reservation.lastname},\n\n"
            f"We regret to inform you that your reservation with reference ID {reservation.reference_id} has been blocklisted.\n\n"
            f"You will no longer be able to make future reservations at JSX Hotel. If you have any concerns, please contact us.\n\n"
            f"Best regards,\n"
            f"JSX Hotel Management"
        )
    else:
        body = (
            f"Dear {reservation.firstname} {reservation.lastname},\n\n"
            f"The settlement status of your reservation with reference ID {reservation.reference_id} has been settled.\n\n"
            f"You are now able to CHECK OUT\n"
            f"Thank you for staying with JSX Hotel. We look forward to serving you again.\n\n"
            f"Best regards,\n"
            f"JSX Hotel Management"
        )

    # Send the email
    try:
        email = EmailMessage(
            subject=subject,
            body=body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[reservation.email] if reservation.email else []
        )
        email.send(fail_silently=False)
        print(f"Email notification sent to {reservation.email} for settlement status {settlement_status}.")
    except Exception as e:
        print(f"Error sending email: {e}")