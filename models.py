from django.db import models
from django.utils.timezone import now
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.hashers import make_password

class OTP(models.Model):
    account = models.ForeignKey('Account', on_delete=models.CASCADE)
    email = models.EmailField(default='default@example.com')
    otp_code = models.CharField(max_length=6)
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        # Check if the OTP is older than 10 minutes
        return timezone.now() > self.created_at + timedelta(minutes=10)

# Accounts model
class Account(models.Model):
    firstname = models.CharField(max_length=255)
    middlename = models.CharField(max_length=255, null=True, blank=True)
    lastname = models.CharField(max_length=255)
    address = models.CharField(max_length=255)
    birthday = models.DateField()
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=128)
    last_login = models.DateTimeField(default=now, blank=True, null=True)

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_staff(self):
        return False

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['email', 'username'], name='unique_account')
        ]
        db_table = 'accounts'
        verbose_name = 'Account'
        verbose_name_plural = 'Accounts'

# HR Account model
class HrAccount(models.Model):
    username = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=128)
    password_status = models.CharField(max_length=45)
    hraccount_status = models.CharField(max_length=45)
    last_login = models.DateTimeField(default=now, blank=True, null=True)

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_staff(self):
        return self.hraccount_status == 'ACTIVE'
    

    class Meta:
        db_table = 'hraccount'
        verbose_name = 'HR Account'
        verbose_name_plural = 'HR Accounts'

# Reservation model
class reservation(models.Model):
    email = models.EmailField()
    firstname = models.CharField(max_length=255, null=True, blank=True)
    middlename = models.CharField(max_length=255, null=True, blank=True)
    lastname = models.CharField(max_length=255, null=True, blank=True)
    reference_id = models.AutoField(primary_key=True)
    check_in = models.DateField()
    check_out = models.DateField()
    room_type = models.CharField(max_length=255)
    typeofbooking = models.CharField(max_length=255)
    status = models.CharField(max_length=255)
    receipt = models.FileField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    cancel_date = models.DateTimeField(null=True, blank=True)
    cancelreason = models.CharField(max_length=255, null=True, blank=True)
    cancelstatus = models.CharField(max_length=50, null=True, blank=True)
    settlements = models.CharField(max_length=50, null=True, blank=True)

    class Meta:
        db_table = 'reservation'
        verbose_name = 'Reservation'
        verbose_name_plural = 'Reservations'

# Room model
class Room(models.Model):
    room_id = models.AutoField(primary_key=True)
    room_type = models.CharField(max_length=50, null=True, blank=True)
    is_occupied = models.BooleanField(default=False)

    class Meta:
        db_table = 'rooms'
        verbose_name = 'Room'
        verbose_name_plural = 'Rooms'

# Admin model
class Admin(models.Model):
    username = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=128)
    last_login = models.DateTimeField(default=now, blank=True, null=True)

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_staff(self):
        return True

    class Meta:
        db_table = 'admin'
        verbose_name = 'Admin'
        verbose_name_plural = 'Admins'

# Archive Accounts model
class ArchiveAccount(models.Model):
    firstname = models.CharField(max_length=255)
    middlename = models.CharField(max_length=255, null=True, blank=True)
    lastname = models.CharField(max_length=255)
    address = models.CharField(max_length=255)
    birthday = models.DateField()
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=128)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['email', 'username'], name='unique_archive_account')
        ]
        db_table = 'archive_accounts'
        verbose_name = 'Archive Account'
        verbose_name_plural = 'Archive Accounts'

# Archive HR Account model
class ArchiveHrAccount(models.Model):
    username = models.CharField(max_length=255)
    password = models.CharField(max_length=128)
    password_status = models.CharField(max_length=45)
    hraccount_status = models.CharField(max_length=45)

    class Meta:
        db_table = 'archive_hraccount'
        verbose_name = 'Archive HR Account'
        verbose_name_plural = 'Archive HR Accounts'

# Archive Reservation model
class ArchiveReservation(models.Model):
    email = models.EmailField()
    firstname = models.CharField(max_length=255, null=True, blank=True)
    middlename = models.CharField(max_length=255, null=True, blank=True)
    lastname = models.CharField(max_length=255, null=True, blank=True)
    reference_id = models.AutoField(primary_key=True)
    check_in = models.DateField()
    check_out = models.DateField()
    room_type = models.CharField(max_length=255)
    typeofbooking = models.CharField(max_length=255)
    status = models.CharField(max_length=255)
    receipt = models.FileField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    cancel_date = models.DateTimeField(null=True, blank=True)
    cancelreason = models.CharField(max_length=255, null=True, blank=True)
    cancelstatus = models.CharField(max_length=50, null=True, blank=True)
    settlements = models.CharField(max_length=50, null=True, blank=True)

    class Meta:
        db_table = 'archive_reservation'
        verbose_name = 'Archive Reservation'
        verbose_name_plural = 'Archive Reservations'

# Room Promotion model
class RoomPromotion(models.Model):
    room_name = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    image = models.FileField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)  # Add this field

    class Meta:
        db_table = 'room_promotions'
        verbose_name = 'Room Promotion'
        verbose_name_plural = 'Room Promotions'


class ArchiveRoomPromotion(models.Model):
    room_name = models.CharField(max_length=255)
    price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)  # New field
    description = models.TextField(null=True, blank=True)
    image = models.FileField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = 'archive_room_promotions'
        verbose_name = 'Archive Room Promotion'
        verbose_name_plural = 'Archive Room Promotions'

# Homepage Image model
class HomepageImage(models.Model):
    image = models.FileField()
    title = models.CharField(max_length=255, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'homepage_images'
        verbose_name = 'Homepage Image'
        verbose_name_plural = 'Homepage Images'

# Archive Homepage Image model
class ArchiveHomepageImage(models.Model):
    image = models.FileField()
    title = models.CharField(max_length=255, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    archived_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'archive_homepage_images'
        verbose_name = 'Archived Homepage Image'
        verbose_name_plural = 'Archived Homepage Images'

class Blocklist(models.Model):
    firstname = models.CharField(max_length=255)
    middlename = models.CharField(max_length=255, null=True, blank=True)
    lastname = models.CharField(max_length=255)
    email = models.EmailField(null=True, blank=True)

    class Meta:
        db_table = 'blocklist'
        verbose_name = 'Blocklist'
        verbose_name_plural = 'Blocklists'