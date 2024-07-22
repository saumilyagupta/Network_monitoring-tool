from django.shortcuts import render , redirect
from network.models import NetworkData
from network.networkutils import *
from network.TCPsniffer import TCPSniffer
from django.http import HttpResponse ,JsonResponse
from django.core.serializers import serialize
from django.views.decorators.http import require_POST
from django.contrib.auth.models import User 
from django.contrib import auth ,messages
from django.db.models import Sum, F
from django.db.models.functions import Cast
from django.db.models import FloatField
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
import logging
logger = logging.getLogger(__name__)
sniffer = TCPSniffer()

def get_top_talkers_by_load(limit=10):
    # Get the total data transferred
    total_data = NetworkData.objects.aggregate(total=Sum('DataLoad'))['total']

    # Query for top talkers
    top_talkers = NetworkData.objects.values('SourceIP').annotate(
        dataTransferred=Sum('DataLoad'),
        percentage=Cast(F('dataTransferred') * 100 / total_data, FloatField())
    ).order_by('-dataTransferred')[:limit]

    # Format the results
    results = [
        {
            "ip": talker['SourceIP'],
            "dataTransferred": round(((talker['dataTransferred']//1024)/1024),2),
            "percentage": round(talker['percentage'], 2)
        }
        for talker in top_talkers
    ]

    # Create the final response
    response = {
        "results": results
    }
    return response 

@login_required
def getUsedData(requesr):
    total_data = NetworkData.objects.aggregate(total=Sum('DataLoad'))['total']
    response = {
        "totalDataUsed": total_data
    }
    return JsonResponse(response)

def index(request):
    return render(request , "main.html")

def startsniffer(request):
    if request.method == 'POST':
        sourceIP = request.POST["sourceIP"]
        destinationIP = request.POST["destinationIP"]
        protocal = request.POST['protocol']
        
        sourceIP = strip_the_space(sourceIP)
        destinationIP = strip_the_space(destinationIP)

        if isValidIPv4(sourceIP):
            sourceIP = sourceIP
        else:
            sourceIP = None
        
        if isValidIPv4(destinationIP):
            destinationIP = destinationIP
        else:
            destinationIP = None


        # Stop the existing sniffer if it's running
        if sniffer.is_sniffer_running():
            sniffer.stop()

        # Start the sniffer with new values
        sniffer.start(sourceIP=sourceIP, destinationIP=destinationIP ,protocal=protocal)
        return HttpResponse("Sniffer Stopped and Restarted with New Values")
    
    return HttpResponse("Invalid Request Method", status=400)

@require_POST
def stopsniffer(request):
    print("Stopsniffer view called")
    try:
        sniffer.stop()
        print("Sniffer stopped successfully")
        return JsonResponse({"message": "Sniffer is stopped."}, status=200)
    except Exception as e:
        print(f"Error stopping sniffer: {str(e)}")
        return JsonResponse({"error": f"Error stopping sniffer: {str(e)}"}, status=500)
    
@login_required
def getData(request):
    if request.method == "GET":
        Data = NetworkData.objects.all().order_by('-id')[:100]
        # serialized_data = serialize('python', Data)
        return JsonResponse({'Data': list(Data.values())})
    
def top_talker(request):
    return render(request, 'top_talker.html')

@login_required
def giveTopTalker(request):
    responce = get_top_talkers_by_load()
    return JsonResponse(responce)

def login(request):
    if request.method == 'POST':
        username = request.POST['Username']
        password = request.POST['password']

        user = auth.authenticate(username=username ,password =password)

        if user is not None :
            auth.login(request,user)
            return redirect('/')
        else:
            messages.info(request , "Credentials Invalid")
            return redirect('login')
    else:    
        return render(request,'login.html')   

def logout(request):
        auth.logout(request)
        return redirect('/')

def Registration(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        password2 = request.POST['confirm-password']

        if password == password2:
            if User.objects.filter(email = email).exists():
                messages.info(request, 'Email already Exist')
                return redirect('Registration')
            elif User.objects.filter(username= username).exists():
                messages.info(request, 'Username already Exist')
                return redirect('Registration')
            else :
                user = User.objects.create_user(username=username,
                                                email=email,
                                                password=password)

                user.save()
                return redirect('login')
        else:
            messages.info(request, 'Passward not Mached')
            return redirect('Registration')
    else:
        return render(request ,"registration.html")

