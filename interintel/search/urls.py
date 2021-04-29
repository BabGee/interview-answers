from django.urls import path
from .views import index, display_products, SearchResultsView

urlpatterns = [
    path('', index, name='index'),
    path('products/', display_products, name='products'),
    path('search/', SearchResultsView.as_view(), name='search_results') 
]