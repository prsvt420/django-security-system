from django.http import JsonResponse
from django.shortcuts import render


def security_system_logs(request):
    with open('security_system/templates/security_system/security_system.log', 'r') as logs_file:
        logs = logs_file.readlines()

    if request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest':
        return JsonResponse({'logs': logs}, safe=False)
    return render(request, 'security_system/logs.html', {'logs': logs})
