from django.db import migrations
from django.utils.timezone import now
from django.contrib.auth.hashers import make_password

def create_admins(apps, schema_editor):
    Admin = apps.get_model('JSXHotel', 'Admin')
    admins = [
        {'username': 'JSXHOTEL2', 'password': 'JSXHOTELPASS2'},
        {'username': 'JSXHOTEL3', 'password': 'JSXHOTELPASS3'},
        {'username': 'JSXHOTEL4', 'password': 'JSXHOTELPASS4'},
        {'username': 'JSXHOTEL5', 'password': 'JSXHOTELPASS5'},
        {'username': 'JSXHOTEL6', 'password': 'JSXHOTELPASS6'},
        {'username': 'JSXHOTEL7', 'password': 'JSXHOTELPASS7'},
        {'username': 'JSXHOTEL8', 'password': 'JSXHOTELPASS8'},
        {'username': 'JSXHOTEL9', 'password': 'JSXHOTELPASS9'},
        {'username': 'JSXHOTEL10', 'password': 'JSXHOTELPASS10'},

    ]

    for admin_data in admins:
        if not Admin.objects.filter(username=admin_data['username']).exists():
            Admin.objects.create(
                username=admin_data['username'],
                password=make_password(admin_data['password']),
                last_login=now()
            )

class Migration(migrations.Migration):
    dependencies = [
        ('JSXHotel', '0011_archiveroompromotion_price'),
    ]

    operations = [
        migrations.RunPython(create_admins),
    ]
