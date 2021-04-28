from django.urls import path
from .views import index, SearchResultsView

urlpatterns = [
    path('', index, name='index'),
    path('search/', SearchResultsView.as_view(), name='search_results') 
]