from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import AttackScenarioViewSet

router = DefaultRouter()
router.register(r'scenarios', AttackScenarioViewSet, basename='scenario')

urlpatterns = [
    path('', include(router.urls)),
]
