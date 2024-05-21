1. Add "security_system" to your INSTALLED_APPS setting like this:
```
INSTALLED_APPS = [
          ...
    'security_system',
]
```

2. Add "security_system.middleware.SecurityMiddleware" to the MIDDLEWARE list:
```
MIDDLEWARE = [
        ...
    'security_system.middleware.SecurityMiddleware',
        ...
]
```

3. Add "LOGGING" at the end of the settings:
```
LOGGING = {
  'version': 1,
  'disable_existing_loggers': False,

  'formatters': {
      'security_system_format': {
          'format': '{asctime} - {levelname} - {filename} - {message}',
          'style': '{',
      },
  },

  'handlers': {
      'security_system_console': {
          'class': 'logging.StreamHandler',
          'formatter': 'security_system_format',
      },

      'security_system_file': {
          'class': 'logging.FileHandler',
          'filename': 'security_system/templates/security_system/security_system.log',
          'formatter': 'security_system_format',
      },
  },

  'loggers': {
      'security_system': {
          'handlers': ['security_system_console', 'security_system_file'],
          'level': 'INFO' if not DEBUG else 'DEBUG',
          'propagate': True,
      },
  },
}
```
4. Add "ALLOWED_HOSTS_ADMIN" at the end of the settings, as well as the IP of the administrators:
```
ALLOWED_HOSTS_ADMIN = [
    ...
]
```
5. Include the security_system URLconf in your project urls.py like this::
```
urlpatterns = [
    path('admin/security_system/', include('security_system.urls', namespace='security_system'), name='security_system'),
    path('admin/', admin.site.urls),
         ...
]
```
6. Run ```python manage.py migrate``` to create the security_system models.

7. Visit http://127.0.0.1:8000/admin/security_system/logs to view the logs
