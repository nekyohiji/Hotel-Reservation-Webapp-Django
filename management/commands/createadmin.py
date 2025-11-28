from django.core.management.base import BaseCommand
from JSXHotel.models import Admin
from django.contrib.auth.hashers import make_password

class Command(BaseCommand):
    help = 'Create the standard admin account'

    def handle(self, *args, **kwargs):
        if not Admin.objects.filter(username='JSXHOTEL_ADMIN').exists():
            Admin.objects.create(
                username='JSXHOTEL_ADMIN',
                password=make_password('JSXHOTELPASSWORD')
            )
            self.stdout.write(self.style.SUCCESS('Admin account created successfully.'))
        else:
            self.stdout.write(self.style.WARNING('Admin account already exists.'))
