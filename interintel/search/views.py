from django.shortcuts import render, redirect
from django.views.generic import View
from django.contrib import messages
from django.db.models import Q

from .models import Product


def index(request):
    return render(request, 'search/index.html')


class SearchResultsView(View):
    def get(self, *args, **kwargs):
        qs =  Product.objects.all()
        query = self.request.GET.get('q')        
        if query: 
            qs = qs.filter(Q(title__icontains=query))
            product_count = qs.count()
            if len(qs) == 0:
                messages.warning(self.request, f'No Product Named {query}')
                return redirect('index')
        elif query == '':
             messages.warning(self.request, 'No Product selected')
             return redirect('index')

        context = {
            'search_query_rslt' : qs,
            'product_count': product_count,
            'query': query
        }
        return render(self.request, 'search/search_results.html', context)
