from django.urls import path
from . import views

urlpatterns = [
    # Front end Paths 
    path("",views.index , name="index"),
    path("getData",views.getData , name="getData"),
    path("login",views.login , name="login"),
    path("Registration",views.Registration , name="Registration"),
    path('toptalker', views.top_talker, name='top_talker'),

    # API paths 
    path("logout",views.logout , name="logout"),
    path('giveTopTalker', views.giveTopTalker, name='giveTopTalker'),
    path('getUsedData', views.getUsedData, name='getUsedData'),
    path("startsniffer",views.startsniffer , name="startsniffer"),
    path("stopsniffer/",views.stopsniffer , name="stopsniffer"),
]