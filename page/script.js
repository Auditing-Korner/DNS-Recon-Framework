document.addEventListener('DOMContentLoaded', async () => {
    try {
        const response = await fetch('providers.json');
        const data = await response.json();
        const providers = data.cloud_providers;
        
        const providersGrid = document.getElementById('providers-grid');
        const filterButtons = document.querySelectorAll('.filter-btn');
        
        function createProviderCard(provider) {
            return `
                <div class="provider-card p-6" data-category="${provider.category}">
                    <div class="flex items-center justify-between mb-4">
                        <img src="${provider.logo}" alt="${provider.name} logo" class="provider-logo">
                        ${provider.global ? '<span class="global-badge">Global</span>' : ''}
                    </div>
                    <h2 class="text-xl font-bold mb-2">${provider.name}</h2>
                    <p class="text-gray-600 mb-2">${provider.category}</p>
                    <div class="mb-4">
                        <a href="${provider.website}" target="_blank" class="text-blue-600 hover:text-blue-800">
                            ${provider.website}
                        </a>
                    </div>
                    <div class="mb-4">
                        <strong class="block mb-2">ASN:</strong>
                        <span class="text-gray-700">${provider.asn}</span>
                    </div>
                    <div>
                        <strong class="block mb-2">DNS Domains:</strong>
                        <div class="flex flex-wrap">
                            ${provider.dns_domains.slice(0, 3).map(domain => 
                                `<span class="dns-domain">${domain}</span>`
                            ).join('')}
                            ${provider.dns_domains.length > 3 ? 
                                `<span class="dns-domain">+${provider.dns_domains.length - 3} more</span>` : 
                                ''}
                        </div>
                    </div>
                </div>
            `;
        }

        function displayProviders(category = 'all') {
            const filteredProviders = category === 'all' 
                ? providers 
                : providers.filter(p => p.category === category);
            
            providersGrid.innerHTML = filteredProviders
                .map(provider => createProviderCard(provider))
                .join('');
        }

        filterButtons.forEach(button => {
            button.addEventListener('click', () => {
                filterButtons.forEach(btn => btn.classList.remove('active'));
                button.classList.add('active');
                displayProviders(button.dataset.category);
            });
        });

        // Initial display
        displayProviders();

    } catch (error) {
        console.error('Error loading providers:', error);
        document.getElementById('providers-grid').innerHTML = `
            <div class="col-span-full text-center text-red-600">
                Error loading providers data. Please try again later.
            </div>
        `;
    }
}); 